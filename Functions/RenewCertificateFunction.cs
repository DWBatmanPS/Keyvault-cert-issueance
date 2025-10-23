using System;
using System.Linq;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Extensions;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Functions;

public class RenewCertificateFunction
{
    private readonly ILogger _logger;
    private readonly KeyVaultService _kvService;
    private readonly CertificateOrderService _orderService;
    private readonly ResponseFactory _responses;
    private readonly DefaultAzureCredential _credential;

    public RenewCertificateFunction(
        ILoggerFactory loggerFactory,
        KeyVaultService kvService,
        CertificateOrderService orderService,
        ResponseFactory responses,
        DefaultAzureCredential credential)
    {
        _logger = loggerFactory.CreateLogger<RenewCertificateFunction>();
        _kvService = kvService;
        _orderService = orderService;
        _responses = responses;
        _credential = credential;
    }

    [Function("RenewCertificate")]
    public async Task Run([TimerTrigger("0 0 2 */2 * *")] TimerInfo timer)
    {
        string correlationId = Guid.NewGuid().ToString("n");
        try
        {
            string certName = Environment.GetEnvironmentVariable("KEYVAULT_CERT_NAME")
                ?? Environment.GetEnvironmentVariable("DOMAIN_NAME")?.Replace('.', '-') ?? "cert";
            string keyVaultName = Environment.GetEnvironmentVariable("KEYVAULT_NAME") ?? "";
            string thresholdRaw = Environment.GetEnvironmentVariable("CERT_RENEWAL_THRESHOLD_DAYS") ?? "15";
            int thresholdDays = int.TryParse(thresholdRaw, out var td) ? td : 15;

            if (string.IsNullOrWhiteSpace(keyVaultName))
            {
                _logger.LogWarning("RenewCertificate CorrelationId={CorrelationId} KEYVAULT_NAME missing; skipping.", correlationId);
                return;
            }

            var currentResult = await _kvService.GetCurrentCertificateAsync(keyVaultName, certName);
            var current = currentResult.meta;
            var getErr = currentResult.error;
            if (getErr != null)
            {
                _logger.LogWarning("RenewCertificate CorrelationId={CorrelationId} fetch error: {Error}", correlationId, getErr.Message);
                return;
            }

            if (current == null)
            {
                _logger.LogInformation("RenewCertificate CorrelationId={CorrelationId} certificate not found; skipping renewal.", correlationId);
                return;
            }

            var remaining = current.NotAfter - DateTimeOffset.UtcNow;
            if (remaining > TimeSpan.FromDays(thresholdDays))
            {
                _logger.LogInformation("RenewCertificate CorrelationId={CorrelationId} certificate healthy. RemainingDays={Days}",
                    correlationId, remaining.TotalDays);
                return;
            }

            string email = Environment.GetEnvironmentVariable("LE_EMAIL") ?? "";
            string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID") ?? "";
            string resourceGroup = Environment.GetEnvironmentVariable("RESOURCE_GROUP") ?? "";
            string dnsZone = Environment.GetEnvironmentVariable("DNS_ZONE") ?? "";
            bool staging = Environment.GetEnvironmentVariable("LE_USE_STAGING")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;
            bool dryRun = Environment.GetEnvironmentVariable("LE_DRY_RUN")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;
            bool cleanupDns = Environment.GetEnvironmentVariable("CLEANUP_DNS")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;
            string? pfxPassword = Environment.GetEnvironmentVariable("PFX_PASSWORD");
            string? accountSecretName = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME");

            int propagationMinutes = ParseIntEnv("MAX_PROPAGATION_MINUTES", 2, 1, 15);
            int challengeMinutes = ParseIntEnv("MAX_CHALLENGE_MINUTES", 5, 1, 15);

            var domains = current.Domains.Length > 0
                ? current.Domains
                : BuildFallbackDomains();

            if (domains.Length == 0)
            {
                _logger.LogWarning("RenewCertificate CorrelationId={CorrelationId} no domains resolved; skipping.", correlationId);
                return;
            }

            SecretClient? secretClient = null;
            if (!string.IsNullOrWhiteSpace(accountSecretName))
                secretClient = new SecretClient(new Uri($"https://{keyVaultName}.vault.azure.net/"), _credential);

            var primary = domains[0];
            var extras = domains.Skip(1).ToArray();

            _logger.LogInformation("RenewCertificate CorrelationId={CorrelationId} renewing cert={CertName} expires={Expires} primary={Primary}",
                correlationId, certName, current.NotAfter, primary);

            var orderResult = await _orderService.IssueCertificateAsync(
                correlationId,
                email,
                staging,
                dryRun,
                cleanupDns,
                primary,
                extras,
                certName,
                subscriptionId,
                resourceGroup,
                dnsZone,
                propagationMinutes,
                challengeMinutes,
                keyVaultName,
                pfxPassword,
                secretClient,
                accountSecretName,
                msg => _logger.LogInformation(msg));

            var meta = orderResult.meta;
            var error = orderResult.error;

            if (error != null)
            {
                _logger.LogError("RenewCertificate CorrelationId={CorrelationId} renewal failed: {Code} {Message}",
                    correlationId, error.Code, error.Message);
                return;
            }

            _logger.LogInformation("RenewCertificate CorrelationId={CorrelationId} renewal complete newVersion={Version} expires={NewExpiry}",
                correlationId, meta!.Version, meta.NotAfter);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RenewCertificate CorrelationId={CorrelationId} unexpected failure.", correlationId);
        }
    }

    private static int ParseIntEnv(string name, int @default, int min, int max)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(raw)) return @default;
        if (!int.TryParse(raw, out var val)) return @default;
        return Math.Clamp(val, min, max);
    }

    private static string[] BuildFallbackDomains()
    {
        var primary = Environment.GetEnvironmentVariable("DOMAIN_NAME") ?? "";
        var extrasRaw = Environment.GetEnvironmentVariable("ADDITIONAL_NAMES") ?? "";
        var extras = extrasRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return new[] { primary }.Concat(extras.Where(e => !string.Equals(e, primary, StringComparison.OrdinalIgnoreCase))).ToArray();
    }
}