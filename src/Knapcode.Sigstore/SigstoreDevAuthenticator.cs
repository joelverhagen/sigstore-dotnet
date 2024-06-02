using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.OpenIddictClientModels;

namespace Knapcode.Sigstore.Cli;

public class SigstoreDevAuthenticator : IAsyncDisposable
{
    private const string MissingExpiration = "No token expiration was returned by Sigstore.";
    private const string MissingIdToken = "No ID token was returned by Sigstore.";
    private const string MissingRefreshToken = "No refresh token was returned by Sigstore.";
    private readonly ServiceProvider _serviceProvider;
    private readonly OpenIddictClientService _client;

    public SigstoreDevAuthenticator()
    {
        var serviceCollection = new ServiceCollection();

        serviceCollection.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowDeviceCodeFlow();
                options.AllowRefreshTokenFlow();
                options.DisableTokenStorage();
                options.UseSystemNetHttp().SetProductInformation(typeof(SigstoreDevAuthenticator).Assembly);

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://oauth2.sigstore.dev/auth", UriKind.Absolute),
                    ClientId = "sigstore",
                    Scopes =
                    {
                        Scopes.OpenId,
                        Scopes.Email,
                        Scopes.OfflineAccess,
                    },
                });
            });

        _serviceProvider = serviceCollection.BuildServiceProvider();
        _client = new OpenIddictClientService(_serviceProvider);
    }

    public async Task<AuthenticationResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var result = await _client.AuthenticateWithRefreshTokenAsync(new RefreshTokenAuthenticationRequest
        {
            RefreshToken = refreshToken,
            DisableUserinfo = true,
            CancellationToken = cancellationToken,
        });

        return new AuthenticationResult(
            result.AccessToken,
            result.AccessTokenExpirationDate ?? throw new InvalidOperationException(MissingExpiration),
            result.IdentityToken ?? throw new InvalidOperationException(MissingIdToken),
            result.RefreshToken ?? throw new InvalidOperationException(MissingRefreshToken));
    }

    public async Task<AuthenticationResult> AuthenticateAsync(Func<DeviceChallenge, Task> onChallengeAsync, CancellationToken cancellationToken = default)
    {
        var codeVerifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

        var challengeResult = await _client.ChallengeUsingDeviceAsync(new()
        {   
            AdditionalDeviceAuthorizationRequestParameters = new Dictionary<string, OpenIddictParameter>
            {
                { Parameters.CodeChallengeMethod, CodeChallengeMethods.Sha256 },
                { Parameters.CodeChallenge, codeChallenge },
            },
            CancellationToken = cancellationToken,
        });

        await onChallengeAsync(new DeviceChallenge(
            challengeResult.VerificationUri,
            challengeResult.UserCode,
            challengeResult.VerificationUriComplete));

        var result = await _client.AuthenticateWithDeviceAsync(new()
        {
            AdditionalTokenRequestParameters = new Dictionary<string, OpenIddictParameter>
            {
                { Parameters.CodeVerifier, codeVerifier },
            },
            DeviceCode = challengeResult.DeviceCode,
            Interval = challengeResult.Interval,
            Timeout = challengeResult.ExpiresIn < TimeSpan.FromMinutes(5) ? challengeResult.ExpiresIn : TimeSpan.FromMinutes(5),
            DisableUserinfo = true,
            CancellationToken = cancellationToken,
        });

        return new AuthenticationResult(
            result.AccessToken,
            result.AccessTokenExpirationDate ?? throw new InvalidOperationException(MissingExpiration),
            result.IdentityToken ?? throw new InvalidOperationException(MissingIdToken),
            result.RefreshToken ?? throw new InvalidOperationException(MissingRefreshToken));
    }

    public ValueTask DisposeAsync()
    {
        return _serviceProvider.DisposeAsync();
    }
}
