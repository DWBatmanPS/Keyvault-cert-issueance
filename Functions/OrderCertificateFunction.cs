using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Models;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Functions;

public class OrderCertificateFunction
{
    private readonly ILogger _logger;
    private readonly CertificateOrderService _orderService;
    private readonly ResponseFactory _responses;
    private readonly DefaultAzureCredential _credential;

    public OrderCertificateFunction(
        ILoggerFactory loggerFactory,
        CertificateOrderService orderService,
        ResponseFactory responses,
        DefaultAzureCredential credential)
    {
        _logger = loggerFactory.CreateLogger<OrderCertificateFunction>();
        _orderService = orderService;
        _responses = responses;
        _credential = credential;
    }

    [Function("OrderCertificate")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        string correlationId = Guid.NewGuid().ToString("n");
        try
        {
            var raw = await new StreamReader(req.Body).ReadToEndAsync();
            OrderRequest? request = string.IsNullOrWhiteSpace(raw) ? null :
                JsonSerializer.Deserialize<OrderRequest>(raw);

            string primaryDomain = request?.PrimaryDomain
                ?? Environment.GetEnvironmentVariable("DOMAIN_NAME")
                ?? "";
            if (string.IsNullOrWhiteSpace(primaryDomain))
                return await Fail(req, correlationId, "validation_error", "Primary domain required.");

            var additional = request?.AdditionalNames ??
                (Environment.GetEnvironmentVariable("ADDITIONAL_NAMES")?
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    ?? Array.Empty<string>());

            string certName = request?.CertificateName
                ?? Environment.GetEnvironmentVariable("KEYVAULT_CERT_NAME")
                ?? primaryDomain.Replace('.', '-');

            bool staging = request?.UseStaging
                ?? (Environment.GetEnvironmentVariable("LE_USE_STAGING")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);
            bool dryRun = request?.DryRun
                ?? (Environment.GetEnvironmentVariable("LE_DRY_RUN")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);
            bool cleanupDns = request?.CleanupDns
                ?? (Environment.GetEnvironmentVariable("CLEANUP_DNS")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);

            int propagationMinutes = ParseIntEnv("MAX_PROPAGATION_MINUTES", 2, 1, 15);
            int challengeMinutes = ParseIntEnv("MAX_CHALLENGE_MINUTES", 5, 1, 15);

            string email = Environment.GetEnvironmentVariable("LE_EMAIL") ?? "";
            string keyVaultName = Environment.GetEnvironmentVariable("KEYVAULT_NAME") ?? "";
            string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID") ?? "";
            string resourceGroup = Environment.GetEnvironmentVariable("RESOURCE_GROUP") ?? "";
            string dnsZone = Environment.GetEnvironmentVariable("DNS_ZONE") ?? "";
            string? pfxPassword = Environment.GetEnvironmentVariable("PFX_PASSWORD");

            if (new[] { keyVaultName, subscriptionId, resourceGroup, dnsZone }.Any(string.IsNullOrWhiteSpace))
                return await Fail(req, correlationId, "validation_error", "Missing required environment variables for issuance.");

            // NEW BLOCK (replaces old accountSecretName + secretClient code)
            string? accountSecretNameBase    = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME");
            string? accountSecretNameStaging = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_STAGING");
            string? accountSecretNameProd    = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_PROD");

            SecretClient? secretClient = null;
            if (!string.IsNullOrWhiteSpace(keyVaultName))
                secretClient = new SecretClient(new Uri($"https://{keyVaultName}.vault.azure.net/"), _credential);

            // Log which secret naming path we expect (optional helpful diagnostics)
            var expectedSecretName = staging
                ? (accountSecretNameStaging ?? (accountSecretNameBase != null ? $"{accountSecretNameBase}-staging" : "blob-fallback"))
                : (accountSecretNameProd ?? accountSecretNameBase ?? "blob-fallback");

            _logger.LogInformation(
                "Order requested CorrelationId={CorrelationId} domains={Domains} cert={CertName} staging={Staging} dryRun={DryRun} secretNameExpected={SecretNameExpected}",
                correlationId,
                string.Join(",", new[] { primaryDomain }.Concat(additional)),
                certName,
                staging,
                dryRun,
                expectedSecretName);

            var issuanceResult = await _orderService.IssueCertificateAsync(
                correlationId,
                email,
                staging,
                dryRun,
                cleanupDns,
                primaryDomain,
                additional,
                certName,
                subscriptionId,
                resourceGroup,
                dnsZone,
                propagationMinutes,
                challengeMinutes,
                keyVaultName,
                pfxPassword,
                secretClient,
                accountSecretNameBase, // pass only the base; service resolves staging/prod env-specific secret
                msg => _logger.LogInformation(msg));

            var meta = issuanceResult.meta;
            var error = issuanceResult.error;

            if (error != null)
                return await WriteJson(req, _responses.Failure<CertificateMetadata>(correlationId, error));

            return await WriteJson(req, _responses.Success(correlationId, meta!));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OrderCertificate unexpected failure CorrelationId={CorrelationId}", correlationId);
            return await WriteJson(req, _responses.Failure<object>(correlationId,
                _responses.Error("internal_error", "Unexpected failure.", ex.Message)));
        }
    }

    private static int ParseIntEnv(string name, int @default, int min, int max)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(raw)) return @default;
        if (!int.TryParse(raw, out var val)) return @default;
        return Math.Clamp(val, min, max);
    }

    private async Task<HttpResponseData> Fail(HttpRequestData req, string cid, string code, string message)
        => await WriteJson(req, _responses.Failure<object>(cid, _responses.Error(code, message)));

    private async Task<HttpResponseData> WriteJson<T>(HttpRequestData req, ApiResponse<T> payload)
    {
        var resp = req.CreateResponse(payload.HasError
            ? System.Net.HttpStatusCode.BadRequest
            : System.Net.HttpStatusCode.OK);
        await resp.WriteStringAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        return resp;
    }
}