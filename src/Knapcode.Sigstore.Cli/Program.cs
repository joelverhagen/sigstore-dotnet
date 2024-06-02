using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Client;
using OpenIddict.Client;
using Spectre.Console;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Knapcode.Sigstore.Cli;

internal class Program
{
    private static async Task Main(string[] args)
    {
        // HttpClient.DefaultProxy = new WebProxy("http://127.0.0.1:8888/", false);

        var host = new HostBuilder()
            .ConfigureServices(services =>
            {
                services.AddSingleton<SigstoreDevAuthenticator>();
                services.AddHostedService<InteractiveService>();
                services.Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true);
            })
            .UseConsoleLifetime()
            .Build();

        await host.RunAsync();
    }
}
