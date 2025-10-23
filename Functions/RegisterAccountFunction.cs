using System;
using System.IO;
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

public class RegisterAccountFunction
{
    private readonly ILogger _logger;
    private readonly AcmeAccountService _acme;
    private readonly ResponseFactory _responses;
    private readonly DefaultAzureCredential _credential;

    public RegisterAccountFunction(
        ILoggerFactory loggerFactory,
        AcmeAccountService acme,
        ResponseFactory responses,
        DefaultAzureCredential credential)
    {
        _logger = loggerFactory.CreateLogger<RegisterAccountFunction>();
        _acme = acme;
        _responses = responses;
        _credential = credential;
    }

    [Function("RegisterAccount")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        var correlationId = Guid.NewGuid().ToString("n");
        try
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            RegisterAccountRequest? request = string.IsNullOrWhiteSpace(body)
                ? null
                : JsonSerializer.Deserialize<RegisterAccountRequest>(body);

            string email = request?.Email
                ?? Environment.GetEnvironmentVariable("LE_EMAIL")
                ?? "";
            if (string.IsNullOrWhiteSpace(email))
                return await WriteJson(req, _responses.Failure<object>(correlationId,
                    _responses.Error("validation_error", "Email is required.")));

            bool staging = request?.UseStaging
                ?? (Environment.GetEnvironmentVariable("LE_USE_STAGING")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);

            string? vaultName = Environment.GetEnvironmentVariable("KEYVAULT_NAME");
            string? acctSecretName = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME");
            SecretClient? secretClient = null;
            if (!string.IsNullOrWhiteSpace(vaultName) && !string.IsNullOrWhiteSpace(acctSecretName))
                secretClient = new SecretClient(new Uri($"https://{vaultName}.vault.azure.net/"), _credential);

            var ensureResult = await _acme.EnsureAccountAsync(email, staging, secretClient, acctSecretName);
            var ctx = ensureResult.Context;
            var error = ensureResult.Error;
            var created = ensureResult.Created;

            if (error != null)
                return await WriteJson(req, _responses.Failure<object>(correlationId, error));

            var result = new
            {
                email,
                staging,
                created
            };
            return await WriteJson(req, _responses.Success(correlationId, result));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RegisterAccount unexpected failure CorrelationId={CorrelationId}", correlationId);
            return await WriteJson(req, _responses.Failure<object>(correlationId,
                _responses.Error("internal_error", "Unexpected failure.", ex.Message)));
        }
    }

    private async Task<HttpResponseData> WriteJson<T>(HttpRequestData req, ApiResponse<T> payload)
    {
        var resp = req.CreateResponse(payload.HasError
            ? System.Net.HttpStatusCode.BadRequest
            : System.Net.HttpStatusCode.OK);
        await resp.WriteStringAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        return resp;
    }
}