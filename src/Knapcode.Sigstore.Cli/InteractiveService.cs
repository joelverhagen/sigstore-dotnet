﻿using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Knapcode.Sigstore.Fulcio;
using Knapcode.Sigstore.FulcioLegacy;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Client;
using Spectre.Console;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace Knapcode.Sigstore.Cli;

public class InteractiveService : BackgroundService
{
    private readonly IHostApplicationLifetime _lifetime;
    private readonly SigstoreDevAuthenticator _service;

    public InteractiveService(
        IHostApplicationLifetime lifetime,
        SigstoreDevAuthenticator service)
    {
        _lifetime = lifetime;
        _service = service;
    }

    private async Task<AuthenticationResult> GetAuthenticationResultAsync(CancellationToken cancellationToken)
    {
        var cacheDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Knapcode.Sigstore");
        var cachePath = Path.Combine(cacheDirectory, "tokens.json.bin");

        if (!Directory.Exists(cacheDirectory))
        {
            Directory.CreateDirectory(cacheDirectory);
        }

        var authenticationResult = await GetAuthenticationResultAsync(cachePath, cancellationToken);

        if (DateTimeOffset.UtcNow > authenticationResult.Expires - TimeSpan.FromSeconds(30))
        {
            try
            {
                authenticationResult = await _service.RefreshAsync(authenticationResult.RefreshToken, cancellationToken);
                SaveAuthenticationResult(cachePath, authenticationResult);
            }
            catch (ProtocolException)
            {
                File.Delete(cachePath);
                authenticationResult = await GetAuthenticationResultAsync(cachePath, cancellationToken);
            }
        }

        return authenticationResult;
    }

    private static void SaveAuthenticationResult(string cachePath, AuthenticationResult authenticationResult)
    {
        var json = JsonSerializer.Serialize(authenticationResult);
        var decrypted = Encoding.UTF8.GetBytes(json);
        var encrypted = ProtectedData.Protect(decrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(cachePath, encrypted);
    }

    private async Task<AuthenticationResult> GetAuthenticationResultAsync(string cachePath, CancellationToken cancellationToken)
    {
        if (File.Exists(cachePath))
        {
            var encrypted = File.ReadAllBytes(cachePath);
            var decrypted = ProtectedData.Unprotect(encrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);
            var json = Encoding.UTF8.GetString(decrypted);

            return JsonSerializer.Deserialize<AuthenticationResult>(json)!;
        }

        var authenticationResult = await _service.AuthenticateAsync(ShowDeviceChallengeAsync, cancellationToken);
        SaveAuthenticationResult(cachePath, authenticationResult);

        return authenticationResult;
    }

    private static Task ShowDeviceChallengeAsync(DeviceChallenge challenge)
    {
        if (challenge.VerificationUriComplete is not null)
        {
            AnsiConsole.MarkupLineInterpolated($"""
                [yellow]Please visit [link]{challenge.VerificationUriComplete}[/] and confirm the
                displayed code is '{challenge.UserCode}' to complete the authentication demand.[/]
                """);
        }

        else
        {
            AnsiConsole.MarkupLineInterpolated($"""
                [yellow]Please visit [link]{challenge.VerificationUri}[/] and enter
                '{challenge.UserCode}' to complete the authentication demand.[/]
                """);
        }

        return Task.CompletedTask;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var source = new TaskCompletionSource<bool>();
        using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource<bool>)state!).SetResult(true), source))
        {
            await source.Task;
        }

        try
        {
            await GenerateCertificateAsync(stoppingToken);
        }

        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("[red]The authentication process was aborted.[/]");
        }

        catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
        {
            AnsiConsole.MarkupLine("[yellow]The authorization was denied by the end user.[/]");
        }

        catch (Exception exception)
        {
            AnsiConsole.MarkupLine("[red]An error occurred while trying to authenticate the user.[/]");
            AnsiConsole.MarkupInterpolated($"[red]{exception}[/]");
            AnsiConsole.MarkupLine("");
        }
    }

    private async Task GenerateCertificateAsync(CancellationToken cancellationToken)
    {
        var authenticationResult = await GetAuthenticationResultAsync(cancellationToken);


        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(authenticationResult.IdToken);

        AnsiConsole.MarkupLine("[green]Authentication successful:[/]");

        var table = new Table()
            .AddColumn(new TableColumn("Claim type").Centered())
            .AddColumn(new TableColumn("Claim value type").Centered())
            .AddColumn(new TableColumn("Claim value").Centered());

        foreach (var claim in token.Claims)
        {
            table.AddRow(
                claim.Type.EscapeMarkup(),
                claim.ValueType.EscapeMarkup(),
                claim.Value.EscapeMarkup());
        }

        AnsiConsole.Write(table);

        using HttpClient httpClient = new HttpClient();
        // httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authenticationResult.AccessToken);
        var fulcioClient = new FulcioClient(httpClient);
        fulcioClient.BaseUrl = "https://fulcio.sigstore.dev/";

        var legacyFulcioClient = new FulcioLegacyClient(httpClient);
        legacyFulcioClient.BaseUrl = "https://fulcio.sigstore.dev/";

        using RSA rsa = RSA.Create(2048);
        
        var request = new CertificateRequest(
            "CN=joel.verhagen@gmail.com",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false, 
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));        

        var response = await fulcioClient.CreateSigningCertificateAsync(new Fulciov2CreateSigningCertificateRequest
        {
           Credentials = new V2Credentials { OidcIdentityToken = authenticationResult.AccessToken },
           CertificateSigningRequest = Encoding.UTF8.GetBytes(request.CreateSigningRequestPem()),
           /*
           PublicKeyRequest = new V2PublicKeyRequest
           {
               ProofOfPossession = rsa.SignData(Encoding.UTF8.GetBytes(token.Subject), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
               PublicKey = new Fulciov2PublicKey
               {
                   Algorithm = V2PublicKeyAlgorithm.RSA_PSS,
                   Content = request.PublicKey.GetRSAPublicKey()!.ExportRSAPublicKeyPem()
               }
           }
           */
        }, cancellationToken);
    }
}