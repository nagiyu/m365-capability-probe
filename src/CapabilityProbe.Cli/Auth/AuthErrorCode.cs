using System.Text.RegularExpressions;

namespace CapabilityProbe.Auth;

/// <summary>
/// Pulls the identity provider's own error code out of whatever the credential threw.
/// The code is the finding: "the app was not granted this permission" and "this resource does not
/// exist in the tenant" both surface as a failed token request and are only told apart by the code.
/// </summary>
public static partial class AuthErrorCode
{
    [GeneratedRegex(@"AADSTS\d{3,6}", RegexOptions.CultureInvariant)]
    private static partial Regex AadstsPattern { get; }

    public static (string Code, string Detail) Describe(Exception exception)
    {
        var chain = Unwind(exception).ToList();

        foreach (var link in chain)
        {
            var match = AadstsPattern.Match(link.Message);
            if (match.Success)
            {
                return (match.Value, FirstLine(link.Message));
            }
        }

        // Azure.Identity wraps MSAL exceptions; MSAL carries a lower-case error code such as
        // "invalid_client" or "interaction_required" on a public ErrorCode property.
        foreach (var link in chain)
        {
            if (link.GetType().GetProperty("ErrorCode")?.GetValue(link) is string code &&
                !string.IsNullOrWhiteSpace(code))
            {
                return (code, FirstLine(link.Message));
            }
        }

        var innermost = chain[^1];
        return (innermost.GetType().Name, FirstLine(innermost.Message));
    }

    private static IEnumerable<Exception> Unwind(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }

    private static string FirstLine(string message)
    {
        var line = message.Split('\n', '\r').FirstOrDefault(l => !string.IsNullOrWhiteSpace(l))?.Trim()
                   ?? message.Trim();
        return line.Length <= 400 ? line : line[..400] + "...";
    }
}
