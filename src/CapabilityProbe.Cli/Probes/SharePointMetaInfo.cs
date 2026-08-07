namespace CapabilityProbe.Probes;

/// <summary>
/// SharePoint's <c>MetaInfo</c> column, which is a document's own property bag rather than a value.
/// <para>
/// Finding 14 measured the label living here - GUID, name, method, and the encryption bit - on three
/// files whose dedicated label columns were all empty. So this is the one place in SharePoint that
/// knows, and reading it is how "the file carries a label" and "the list knows about it" can be told
/// apart. The two turned out to be different questions.
/// </para>
/// <para>
/// The format is [MS-FPSE]'s metadict: one entry per line, <c>name:TYPE|value</c>, where TYPE is a
/// two-letter code (<c>SW</c> for a string, <c>SR</c> for a version, and so on). The value may itself
/// contain colons and is taken whole after the first pipe.
/// </para>
/// </summary>
public static class SharePointMetaInfo
{
    public sealed record Entry(string Name, string Type, string Value);

    /// <summary>
    /// What one label stamped into a document looks like once its entries are gathered up. Every
    /// field is nullable because this reports what a file carries, and a file carrying half of a
    /// label is a finding rather than a parse error.
    /// </summary>
    public sealed record Label(string Id)
    {
        public string? Name { get; init; }
        public string? Enabled { get; init; }
        public string? SetDate { get; init; }
        public string? Method { get; init; }
        public string? SiteId { get; init; }
        public string? ContentBits { get; init; }

        /// <summary>
        /// Bit 0x8 of <c>ContentBits</c> is ENCRYPT. Null when the entry did not arrive or was not a
        /// number - which must not read as "not encrypted", since that is precisely the confusion
        /// finding 14 is about.
        /// </summary>
        public bool? Encrypts =>
            int.TryParse(ContentBits, out var bits) ? (bits & 0x8) != 0 : null;

        public string Describe =>
            $"{Id}{(Name is null ? "" : $" ({Name})")}" +
            $"{Encrypts switch { true => " encrypts", false => " does not encrypt", null => "" }}";
    }

    public static IReadOnlyList<Entry> Parse(string? metaInfo)
    {
        var entries = new List<Entry>();
        if (string.IsNullOrWhiteSpace(metaInfo))
        {
            return entries;
        }

        foreach (var line in metaInfo.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':');
            var pipe = line.IndexOf('|');

            // Both separators, in that order, or this is not an entry. Anything else is left out
            // rather than guessed at - a half-read property bag would be reported as a file's state.
            if (colon < 0 || pipe < colon)
            {
                continue;
            }

            entries.Add(new Entry(
                line[..colon].Trim(),
                line[(colon + 1)..pipe].Trim(),
                line[(pipe + 1)..]));
        }

        return entries;
    }

    /// <summary>
    /// The labels stamped into the document, gathered from entries named
    /// <c>MSIP_Label_&lt;guid&gt;_&lt;field&gt;</c>. Several labels can be present at once - a file
    /// relabelled keeps the old entries unless something removes them - so this returns all of them.
    /// </summary>
    public static IReadOnlyList<Label> Labels(IReadOnlyList<Entry> entries)
    {
        const string prefix = "MSIP_Label_";
        var byId = new Dictionary<string, Label>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (!entry.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var rest = entry.Name[prefix.Length..];
            var underscore = rest.IndexOf('_');
            if (underscore <= 0)
            {
                continue;
            }

            var id = rest[..underscore];
            var field = rest[(underscore + 1)..];
            var label = byId.TryGetValue(id, out var existing) ? existing : new Label(id);

            byId[id] = field.ToLowerInvariant() switch
            {
                "name" => label with { Name = entry.Value },
                "enabled" => label with { Enabled = entry.Value },
                "setdate" => label with { SetDate = entry.Value },
                "method" => label with { Method = entry.Value },
                "siteid" => label with { SiteId = entry.Value },
                "contentbits" => label with { ContentBits = entry.Value },
                _ => label,
            };
        }

        return byId.Values.ToList();
    }
}
