using System.Security.Claims;

namespace Knapcode.Sigstore.Cli;

public record AuthenticationResult(
    string AccessToken,
    DateTimeOffset Expires,
    string IdToken,
    string RefreshToken);
