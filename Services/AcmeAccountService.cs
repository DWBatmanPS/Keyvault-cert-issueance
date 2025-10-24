using System;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Certes;
using Certes.Acme;
using Keyvault_cert_issueance.Models;

namespace Keyvault_cert_issueance.Services;

public class AcmeAccountService
{
    private readonly StorageAccountService _storage;
    private readonly ResponseFactory _responses;

    public AcmeAccountService(StorageAccountService storage, ResponseFactory responses)
    {
        _storage = storage;
        _responses = responses;
    }

    public Uri GetServer(bool staging) =>
        staging
            ? WellKnownServers.LetsEncryptStagingV2
            : WellKnownServers.LetsEncryptV2;

    public async Task<(AcmeContext? Context, ApiError? Error, bool Created)> EnsureAccountAsync(
        string email,
        bool staging,
        SecretClient? secretClient,
        string? secretName)
    {
        var server = GetServer(staging);

        string? explicitProd = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_PROD");
        string? explicitStaging = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_STAGING");

        // Resolve which secret name to use (prod vs staging vs fallback)
        string? resolvedSecretName = null;
        if (secretClient != null)
        {
            if (staging && !string.IsNullOrWhiteSpace(explicitStaging))
                resolvedSecretName = explicitStaging.Trim();
            else if (!staging && !string.IsNullOrWhiteSpace(explicitProd))
                resolvedSecretName = explicitProd.Trim();
            else if (!string.IsNullOrWhiteSpace(secretName))
                resolvedSecretName = staging ? $"{secretName.Trim()}-staging" : secretName.Trim();
        }

        // Use the resolved name if available
        if (!string.IsNullOrWhiteSpace(resolvedSecretName) && secretClient != null)
        {
            try
            {
                KeyVaultSecret secret = await secretClient.GetSecretAsync(resolvedSecretName);
                var key = KeyFactory.FromPem(secret.Value);
                var ctx = new AcmeContext(server, key);
                _ = await ctx.Account();
                return (ctx, null, false);
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                var newKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                var newCtx = new AcmeContext(server, newKey);
                await newCtx.NewAccount(email, true);
                await secretClient.SetSecretAsync(new KeyVaultSecret(resolvedSecretName, newKey.ToPem()));
                return (newCtx, null, true);
            }
            catch (Exception ex)
            {
                return (null,
                    _responses.Error("account_error",
                        $"Failed loading ACME account from Key Vault secret '{resolvedSecretName}'.",
                        ex.Message),
                    false);
            }
        }

        // Blob fallback (shared per staging/prod)
        try
        {
            var pem = await _storage.ReadAccountKeyPemAsync(staging);
            if (pem != null)
            {
                var key = KeyFactory.FromPem(pem);
                var ctx = new AcmeContext(server, key);
                _ = await ctx.Account();
                return (ctx, null, false);
            }

            var newKey2 = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var newCtx2 = new AcmeContext(server, newKey2);
            await newCtx2.NewAccount(email, true);
            await _storage.WriteAccountKeyPemAsync(staging, newKey2.ToPem());
            return (newCtx2, null, true);
        }
        catch (Exception ex)
        {
            return (null,
                _responses.Error("account_error", "Failed to create or load ACME account.", ex.Message),
                false);
        }
    }
}