namespace CapabilityProbe.Configuration;

/// <summary>
/// The settings the probe needs. The six required ones are not optional-by-convenience: each is
/// either supplied by the operator or the run is refused up front. The certificate is the exception -
/// it adds an identity when present, and its absence is reported rather than assumed.
/// </summary>
public sealed class ProbeOptions
{
    /// <summary>Directory (tenant) ID of the Entra tenant the app registration lives in.</summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>Application (client) ID of the app registration under test.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client secret of the app registration. Keep this in user-secrets.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Path to a PKCS#12 (<c>.pfx</c>) file holding a certificate and its private key, for the
    /// app-only leg that authenticates with a certificate instead of the secret.
    /// <para>
    /// Optional. Left empty, that leg is reported as not run rather than quietly skipped - an absent
    /// measurement and a measurement of nothing are different things.
    /// </para>
    /// <para>
    /// A file path rather than an inline blob because the same value has to work from a developer's
    /// machine and from CI, and a path works in both: CI writes its secret to a temporary file first.
    /// One input, one code path.
    /// </para>
    /// </summary>
    public string ClientCertificatePath { get; set; } = string.Empty;

    /// <summary>Password protecting the <c>.pfx</c>, if it has one. Keep it in user-secrets.</summary>
    public string ClientCertificatePassword { get; set; } = string.Empty;

    /// <summary>True when a certificate was configured, whether or not it turns out to be loadable.</summary>
    public bool HasCertificate => !string.IsNullOrWhiteSpace(ClientCertificatePath);

    /// <summary>Site collection URL in the form <c>https://&lt;host&gt;/sites/&lt;name&gt;</c>.</summary>
    public string SiteUrl { get; set; } = string.Empty;

    /// <summary>
    /// One or more paths to read, separated by <c>|</c>.
    /// <para>
    /// Each path is relative to the root of the site's default document library and does not include
    /// the library's own name - a file sitting directly in that library is just <c>/test.docx</c>.
    /// This is what the probe appends to <c>/drive/root:</c>, and prefixing it with the library name
    /// looks for a folder of that name inside the library instead.
    /// </para>
    /// <para>
    /// A delimited string rather than an array because this value has to survive five configuration
    /// layers and a workflow dispatch input, and an array is awkward in four of the six.
    /// <c>|</c> is one of the characters SharePoint refuses in a file or folder name, so it can never
    /// occur inside a path and never needs escaping.
    /// </para>
    /// </summary>
    public string FilePaths { get; set; } = string.Empty;

    /// <summary>The paths, split and trimmed. Empty when none are configured.</summary>
    public IReadOnlyList<string> Files =>
        FilePaths.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Sign-in name the operator should use for the delegated (device code) leg.</summary>
    public string DelegatedUserHint { get; set; } = string.Empty;

    /// <summary>
    /// Which identities a run should establish: <c>all</c>, or <c>app-only</c> to leave the delegated
    /// leg alone.
    /// <para>
    /// The delegated leg needs a person at a browser, and there are places a run happens where there
    /// is no person - and times when the sign-in is refused for reasons that have nothing to do with
    /// what the app can reach. Narrowing the run is better than a report full of rows that failed for
    /// a reason the report is not about.
    /// </para>
    /// <para>
    /// It narrows the run; it does not hide it. The delegated rows still appear, as not run, saying
    /// that this is what the run was asked for. A leg that vanishes from a report reads as a leg that
    /// was never worth measuring.
    /// </para>
    /// </summary>
    public string Identities { get; set; } = string.Empty;

    /// <summary>The two values <see cref="Identities"/> accepts, for validation and for messages.</summary>
    public const string AllIdentities = "all";
    public const string AppOnlyIdentities = "app-only";

    /// <summary>True unless the run was explicitly narrowed to the application's own identities.</summary>
    public bool RunDelegated =>
        !string.Equals(Identities.Trim(), AppOnlyIdentities, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Paths to protected files on this machine, separated by <c>|</c>, for <c>consume</c> to open.
    /// </summary>
    public string ProtectedFilePaths { get; set; } = string.Empty;

    /// <summary>
    /// Paths to protected files inside the site's default document library, separated by <c>|</c>,
    /// in the same shape as <see cref="FilePaths"/> - <c>/probe.docx</c> for a file sitting directly
    /// in the library. <c>consume</c> fetches each with the app's own token before any leg runs, and
    /// deletes them after.
    /// <para>
    /// The alternative to handing the files themselves to a run. Which file is being opened is what a
    /// run is about, and things a run is about are its inputs; a stored credential is for the values
    /// that never change between runs. Putting a file where the app can already read it turns a
    /// variable blob into a path.
    /// </para>
    /// <para>
    /// It also means the fetch is measured. Whether the bytes arrive still protected is not something
    /// this asserts - the legs below report what each file turned out to be, and a file that arrived
    /// decrypted is reported as unprotected rather than opened as if it were not.
    /// </para>
    /// </summary>
    public string ProtectedSiteFiles { get; set; } = string.Empty;

    /// <summary>The site paths, split and trimmed.</summary>
    public IReadOnlyList<string> ProtectedSiteFileList =>
        ProtectedSiteFiles.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>The local paths, split and trimmed.</summary>
    public IReadOnlyList<string> ProtectedFilePathList =>
        ProtectedFilePaths.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Addresses to put in <c>FileEngineSettings.DelegatedUserEmail</c>, one leg each, separated by
    /// <c>|</c>. A leg with the value unset is always added on top of these.
    /// <para>
    /// The tool is not told which of them is supposed to have rights. It runs each and reports what
    /// came back; which one was the control is an argument about a tenant, and it belongs in prose.
    /// </para>
    /// </summary>
    public string DelegatedUserEmails { get; set; } = string.Empty;

    /// <summary>The addresses, split and trimmed.</summary>
    public IReadOnlyList<string> DelegatedUsers =>
        DelegatedUserEmails.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Holds <c>FileEngineSettings.Identity</c> still while <c>DelegatedUserEmail</c> varies.
    /// <para>
    /// Left empty, the two move together, and a difference between legs is a fact about the pair.
    /// Set, only one thing changes between legs - which is the stronger measurement and the reason
    /// this knob exists. Either way the report says which was done.
    /// </para>
    /// </summary>
    public string MipIdentityEmail { get; set; } = string.Empty;

    /// <summary>
    /// How many items to ask each collection for at a time, as <c>$top</c>. Empty leaves it off and
    /// takes whatever the service considers a page.
    /// <para>
    /// It exists so that paging can be measured without first putting hundreds of files somewhere.
    /// Set it to 2 against a library of seven and every route has to follow a continuation link to
    /// answer at all - which is the part of paging that lives in this tool rather than in the service.
    /// </para>
    /// <para>
    /// What it cannot measure is the other half: whether a service caps a page below what was asked
    /// for, or stops offering links past some depth. That needs real volume, and the report says which
    /// of the two a given run was.
    /// </para>
    /// </summary>
    public string PageSize { get; set; } = string.Empty;

    /// <summary>The requested page size, or null when it was not set or was not a positive number.</summary>
    public int? RequestedPageSize =>
        int.TryParse(PageSize.Trim(), out var value) && value > 0 ? value : null;

    /// <summary>
    /// How many pages a route may follow before it stops. Empty means <see cref="DefaultPageLimit"/>.
    /// <para>
    /// A limit is not a silent truncation as long as it is reported, and reaching it is reported: the
    /// route says it stopped at the limit with more waiting, not that the collection ended. A route
    /// that walked 20 pages and one that walked 20 of 400 are the same number of calls and completely
    /// different measurements.
    /// </para>
    /// </summary>
    public string PageLimit { get; set; } = string.Empty;

    /// <summary>Pages a route follows when <see cref="PageLimit"/> says nothing.</summary>
    public const int DefaultPageLimit = 20;

    /// <summary>The page limit in force for this run.</summary>
    public int PagesToFollow =>
        int.TryParse(PageLimit.Trim(), out var value) && value > 0 ? value : DefaultPageLimit;

    /// <summary>
    /// Application (client) ID of a <em>second</em> app registration, used only by <c>inventory</c>.
    /// <para>
    /// Empty, <c>inventory</c> falls back to the probe's own registration and reports that it did.
    /// That is not a degraded mode to be hidden - running the same inventory from a weak registration
    /// and a strong one, and reading where the blanks move, is the measurement this whole tool is
    /// about. The report says which registration answered.
    /// </para>
    /// </summary>
    public string InventoryClientId { get; set; } = string.Empty;

    /// <summary>Path to the second registration's <c>.pfx</c>.</summary>
    public string InventoryCertificatePath { get; set; } = string.Empty;

    /// <summary>Password for <see cref="InventoryCertificatePath"/>, if it has one.</summary>
    public string InventoryCertificatePassword { get; set; } = string.Empty;

    /// <summary>
    /// Client secret for the second registration. Present for completeness and expected to stay empty:
    /// the one route <c>inventory</c> cannot do without - SharePoint REST - refuses secrets outright
    /// (finding 5, and Microsoft's own statement that every option other than a certificate is blocked).
    /// A secret here would buy nothing and would put a broadly-permissioned credential in CI.
    /// </summary>
    public string InventoryClientSecret { get; set; } = string.Empty;

    /// <summary>The app registration every subcommand except <c>inventory</c> speaks as.</summary>
    public AppCredentials ProbeApp => new(
        TenantId, ClientId, ClientSecret, ClientCertificatePath, ClientCertificatePassword,
        "the probe's own app registration");

    /// <summary>
    /// The registration <c>inventory</c> speaks as: its own when configured, the probe's otherwise.
    /// The label travels with it so the report can say which one answered rather than leaving a reader
    /// to infer it from which columns came back empty.
    /// </summary>
    public AppCredentials InventoryApp =>
        string.IsNullOrWhiteSpace(InventoryClientId)
            ? ProbeApp with { Label = "the probe's app registration (InventoryClientId is not set)" }
            : new AppCredentials(
                TenantId, InventoryClientId, InventoryClientSecret,
                InventoryCertificatePath, InventoryCertificatePassword,
                "the inventory app registration");

    /// <summary>Host name taken from <see cref="SiteUrl"/>. Used to build the SharePoint scope.</summary>
    public string SiteHost =>
        Uri.TryCreate(SiteUrl, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;

    /// <summary>Server-relative path taken from <see cref="SiteUrl"/>, e.g. <c>/sites/name</c>.</summary>
    public string SiteServerRelativePath =>
        Uri.TryCreate(SiteUrl, UriKind.Absolute, out var uri)
            ? uri.AbsolutePath.TrimEnd('/')
            : string.Empty;
}
