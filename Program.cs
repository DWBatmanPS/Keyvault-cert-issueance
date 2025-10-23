using System;
using Azure.Identity;
using Azure.ResourceManager;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Infrastructure;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance;

public static class Program
{
    public static void Main(string[] args)
    {
        var host = new HostBuilder()
            .ConfigureFunctionsWorkerDefaults()
            .ConfigureServices(services =>
            {
                // Core credential (will try managed identity in Azure; dev tools locally).
                services.AddSingleton(new DefaultAzureCredential());

                // ArmClient for DNS / other ARM operations.
                services.AddSingleton(sp =>
                    new ArmClient(sp.GetRequiredService<DefaultAzureCredential>()));

                // Application-specific storage service (uses APP_STORAGE_ACCOUNT_NAME + DefaultAzureCredential).
                // NOTE: Ensure you updated StorageAccountService to use identity (no connection string).
                services.AddSingleton<StorageAccountService>();

                // Register other issuance services (AcmeAccountService, DnsChallengeService, etc.)
                services.RegisterCertificateIssuanceServices();

                // Optional: Adjust logging filters if you want more detail.
                services.AddLogging(logging =>
                {
                    logging.SetMinimumLevel(LogLevel.Information);
                    // To temporarily increase verbosity:
                    // logging.SetMinimumLevel(LogLevel.Debug);
                });
            })
            .Build();

        // Startup diagnostics (helpful when running in Azure)
        var logger = host.Services.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Startup");

        var azureWebJobsStorage = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
        if (string.IsNullOrWhiteSpace(azureWebJobsStorage))
        {
            logger.LogCritical("AzureWebJobsStorage not configured. Host will fail to manage leases.");
        }
        else
        {
            var usesKey = azureWebJobsStorage.Contains("AccountKey=", StringComparison.OrdinalIgnoreCase);
            logger.LogInformation("Host storage configured. SharedKeyPresent={SharedKeyPresent}", usesKey);
        }

        var appStorageName = Environment.GetEnvironmentVariable("APP_STORAGE_ACCOUNT_NAME");
        if (string.IsNullOrWhiteSpace(appStorageName))
        {
            logger.LogWarning("APP_STORAGE_ACCOUNT_NAME not set. ACME account key persistence will fail.");
        }
        else
        {
            logger.LogInformation("Application storage (identity-based) targeting account: {AppStorage}", appStorageName);
        }

        host.Run();
    }
}