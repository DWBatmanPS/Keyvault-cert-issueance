using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Certes;
using Certes.Acme;
using Certes.Pkcs;
using Keyvault_cert_issueance.Models;
using System.Security.Cryptography.X509Certificates;

namespace Keyvault_cert_issueance.Services;

public class CertificateOrderService
{
    private readonly AcmeAccountService _accountService;
    private readonly DnsChallengeService _dnsService;
    private readonly KeyVaultService _kvService;
    private readonly ResponseFactory _responses;

    private static readonly ConcurrentDictionary<string, System.Threading.SemaphoreSlim> _locks = new();

    public CertificateOrderService(
        AcmeAccountService accountService,
        DnsChallengeService dnsService,
        KeyVaultService kvService,
        ResponseFactory responses)
    {
        _accountService = accountService;
        _dnsService = dnsService;
        _kvService = kvService;
        _responses = responses;
    }


public async Task<(CertificateMetadata? meta, ApiError? error)> IssueCertificateAsync(
    string correlationId,
    string email,
    bool staging,
    bool dryRun,
    bool cleanupDns,
    string primaryDomain,
    IEnumerable<string> additionalNames,
    string certificateName,
    string subscriptionId,
    string resourceGroup,
    string dnsZone,
    int propagationMinutes,
    int challengeMinutes,
    string keyVaultName,
    string? pfxPassword,
    SecretClient? secretClient,
    string? accountSecretName,
    Action<string>? log)
{
    var allDomains = new List<string> { primaryDomain };
    allDomains.AddRange(additionalNames.Where(a => !string.Equals(a, primaryDomain, StringComparison.OrdinalIgnoreCase)));
    allDomains = allDomains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    var invalid = allDomains.Where(d =>
        !d.Equals(dnsZone, StringComparison.OrdinalIgnoreCase) &&
        !d.EndsWith("." + dnsZone, StringComparison.OrdinalIgnoreCase)).ToList();
    if (invalid.Any())
        return (null, _responses.Error("domain_validation", $"Domains outside zone '{dnsZone}'.", string.Join(", ", invalid)));

    var sem = _locks.GetOrAdd(certificateName, _ => new System.Threading.SemaphoreSlim(1, 1));
    await sem.WaitAsync();
    try
    {
        var acct = await _accountService.EnsureAccountAsync(email, staging, secretClient, accountSecretName);
        var acmeCtx = acct.Context;
        if (acct.Error != null) return (null, acct.Error);
        log?.Invoke($"[{correlationId}] ACME account {(acct.Created ? "created" : "loaded")} staging={staging}");

        if (dryRun)
        {
            return (new CertificateMetadata
            {
                CertificateName = certificateName,
                Version = "dry-run",
                NotBefore = DateTimeOffset.UtcNow,
                NotAfter = DateTimeOffset.UtcNow.AddDays(90),
                Domains = allDomains.ToArray(),
                Renewed = false
            }, null);
        }

        // Order + DNS challenges
        var order = await acmeCtx!.NewOrder(allDomains);
        var authzContexts = await order.Authorizations();
        var dnsErr = await _dnsService.FulfillChallengesAsync(
            acmeCtx,
            authzContexts,
            subscriptionId,
            resourceGroup,
            dnsZone,
            cleanupDns,
            propagationMinutes,
            challengeMinutes,
            log);
        if (dnsErr != null) return (null, dnsErr);

        // CSR
        var csrKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
        var csrInfo = new CsrInfo { CommonName = primaryDomain };
        await order.Generate(csrInfo, csrKey);

        // Download chain
        var certChain = await order.Download(); // CertificateChain (leaf + issuers as IEncodable)
        var leafDer = certChain.Certificate.ToDer();
        var issuerDers = certChain.Issuers?.Select(i => i.ToDer()).ToList() ?? new List<byte[]>();

        // Subject logging (best effort)
        string TrySubject(byte[] der)
        {
            try { return new X509Certificate2(der).Subject; }
            catch { return "<unparseable>"; }
        }
        log?.Invoke($"[{correlationId}] Leaf='{TrySubject(leafDer)}' Issuers='{string.Join(" | ", issuerDers.Select(TrySubject))}' Count={issuerDers.Count}");

        byte[] pfxBytes;
        bool chainBuiltNormally = false;
        bool leafFallbackUsed = false;
        bool allowLeafFallback = (Environment.GetEnvironmentVariable("LEAF_ONLY_FALLBACK")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);

        // Primary (standard) path
        try
        {
            var pfxBuilder = certChain.ToPfx(csrKey); // lets Certes assemble chain
            pfxBytes = pfxBuilder.Build(certificateName, pfxPassword);
            chainBuiltNormally = true;
            log?.Invoke($"[{correlationId}] PFX built via certChain.ToPfx.");
        }
        catch (Exception standardEx)
        {
            log?.Invoke($"[{correlationId}] Standard PFX build failed: {standardEx.Message}; attempting manual chain.");

            try
            {
                var manualBuilder = new PfxBuilder(leafDer, csrKey);
                foreach (var issuerDer in issuerDers)
                {
                    try
                    {
                        manualBuilder.AddIssuer(issuerDer);
                    }
                    catch (Exception addEx)
                    {
                        log?.Invoke($"[{correlationId}] Issuer add failed for '{TrySubject(issuerDer)}': {addEx.Message}");
                    }
                }
                pfxBytes = manualBuilder.Build(certificateName, pfxPassword);
                log?.Invoke($"[{correlationId}] PFX built via manual issuer addition.");
            }
            catch (Exception manualEx)
            {
                log?.Invoke($"[{correlationId}] Manual chain build failed: {manualEx.Message}");

                if (allowLeafFallback)
                {
                    try
                    {
                        var leafBuilder = new PfxBuilder(leafDer, csrKey);
                        pfxBytes = leafBuilder.Build(certificateName, pfxPassword);
                        leafFallbackUsed = true;
                        log?.Invoke($"[{correlationId}] Leaf-only fallback succeeded.");
                    }
                    catch (Exception leafEx)
                    {
                        return (null, _responses.Error(
                            "chain_error",
                            "Certificate chain assembly failed (leaf fallback also failed).",
                            $"{standardEx.Message} | {manualEx.Message} | {leafEx.Message}"));
                    }
                }
                else
                {
                    return (null, _responses.Error(
                        "chain_error",
                        "Certificate chain assembly failed.",
                        $"{standardEx.Message} | {manualEx.Message}"));
                }
            }
        }

        // Import to Key Vault
        var importResult = await _kvService.ImportCertificateVersionAsync(
            keyVaultName,
            certificateName,
            pfxBytes,
            pfxPassword,
            allDomains.ToArray(),
            renewed: false);

        if (importResult.error != null) return (null, importResult.error);

        if (!chainBuiltNormally && leafFallbackUsed)
            log?.Invoke($"[{correlationId}] Imported leaf-only certificate (intermediate(s) missing).");

        return (importResult.meta, null);
    }
    catch (Exception ex)
    {
        return (null, _responses.Error("order_error", "Unexpected failure during issuance.", ex.Message));
    }
    finally
    {
        sem.Release();
    }
}
}