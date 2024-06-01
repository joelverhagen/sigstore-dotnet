namespace Knapcode.Sigstore.Cli;

public record DeviceChallenge(
    Uri VerificationUri,
    string UserCode,
    Uri? VerificationUriComplete);
