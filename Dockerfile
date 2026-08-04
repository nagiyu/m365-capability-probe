# Runs the probe on Linux, which the Information Protection SDK needs and Windows no longer has to
# provide. The SDK ships one NuGet package per platform and only the platform packages carry native
# binaries; this image pairs the Ubuntu 24.04 package with the Ubuntu 24.04 .NET image, because
# .NET 10 publishes no 22.04 tag and a hand-installed SDK would be one more thing to get wrong.
#
# Nothing here is required for the HTTP subcommands - auth, access, sharepoint and acl run anywhere
# .NET does. The image exists for 'mip' and what is built on top of it.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble

# What the SDK's four native libraries ask for, read out of the binaries with objdump rather than
# taken from a page. Leaving one out produces "LoadLibrary failed with error code 0", which names the
# library that failed to load and not the one it could not find - so the list is kept next to the one
# the 'mip' subcommand checks at run time, and the two are meant to stay in step.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3t64 \
        libsecret-1-0 \
        libglib2.0-0t64 \
        libcurl4t64 \
        libxml2 \
        libuuid1 \
        libgsf-1-114 \
        libgmime-3.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Restore before the sources are copied, so editing a .cs file does not re-download the SDK - which
# is a few hundred megabytes of native binaries.
COPY M365CapabilityProbe.sln .
COPY src/CapabilityProbe.Cli/CapabilityProbe.Cli.csproj src/CapabilityProbe.Cli/
RUN dotnet restore M365CapabilityProbe.sln

COPY . .
RUN dotnet publish src/CapabilityProbe.Cli -c Release -o /app

# The probe writes its JSON under <working directory>/reports, so the working directory is not itself
# called reports - that produced /reports/reports. Mounting a volume on the inner path keeps the
# files after the container exits; without one they go with it, which for a measurement tool is the
# wrong default to leave unsaid.
#
#   docker run --rm -v "$PWD/reports:/work/reports" capability-probe mip
WORKDIR /work
VOLUME /work/reports

ENTRYPOINT ["dotnet", "/app/capability-probe.dll"]
CMD ["help"]
