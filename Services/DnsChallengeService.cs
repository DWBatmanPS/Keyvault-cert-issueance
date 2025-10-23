using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;
using Certes; // AcmeContext
using Certes.Acme; // IAuthorizationContext, IChallengeContext
using Certes.Acme.Resource; // ChallengeStatus
using DnsClient;
using Keyvault_cert_issueance.Models;

namespace Keyvault_cert_issueance.Services;

public class DnsChallengeService
{
    private readonly ArmClient _armClient;

    public DnsChallengeService(ArmClient armClient)
    {
        _armClient = armClient;
    }

    private (ApiError? error, DnsZoneResource? zone) GetZone(string subscriptionId, string resourceGroup, string dnsZone)
    {
        try
        {
            var zoneId = new Azure.Core.ResourceIdentifier(
                $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/dnszones/{dnsZone}");
            var zone = _armClient.GetDnsZoneResource(zoneId);
            return (null, zone);
        }
        catch (Exception ex)
        {
            return (new ApiError
            {
                Code = "dns_zone_error",
                Message = "Failed to get DNS zone.",
                Details = new[] { ex.Message }
            }, null);
        }
    }

    public async Task<ApiError?> FulfillChallengesAsync(
        AcmeContext acme,
        IEnumerable<IAuthorizationContext> authzContexts,
        string subscriptionId,
        string resourceGroup,
        string dnsZone,
        bool cleanup,
        int propagationMinutes,
        int challengeMinutes,
        Action<string>? log = null)
    {
        var (err, zoneResource) = GetZone(subscriptionId, resourceGroup, dnsZone);
        if (err != null) return err;

        var txtCollection = zoneResource!.GetDnsTxtRecords();
        var lookup = new LookupClient(new LookupClientOptions { Timeout = TimeSpan.FromSeconds(5), Retries = 2 });

        foreach (var authCtx in authzContexts)
        {
            // Get challenge contexts (not just the resource)
            var challengeContexts = await authCtx.Challenges();
            var dnsCtx = challengeContexts.FirstOrDefault(c => c.Type == "dns-01");
            if (dnsCtx == null)
                return new ApiError { Code = "challenge_missing", Message = "dns-01 challenge missing for one authorization." };

            // Domain from authorization resource (to know which record to create)
            var authResource = await authCtx.Resource();
            var domain = authResource.Identifier.Value;

            var dnsValue = acme.AccountKey.DnsTxt(dnsCtx.Token);
            var recordRelativeName = ComputeRecordRelativeName(domain, dnsZone);
            log?.Invoke($"Preparing TXT record for {domain} -> {recordRelativeName}");

            // Upsert TXT record
            DnsTxtRecordResource? existing = null;
            await foreach (var r in txtCollection)
            {
                if (string.Equals(r.Data.Name, recordRelativeName, StringComparison.OrdinalIgnoreCase))
                {
                    existing = r;
                    break;
                }
            }

            if (existing == null)
            {
                var data = new DnsTxtRecordData { TtlInSeconds = 60 };
                data.DnsTxtRecords.Add(new DnsTxtRecordInfo { Values = { dnsValue } });
                await txtCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, recordRelativeName, data);
            }
            else
            {
                existing.Data.DnsTxtRecords.Clear();
                existing.Data.DnsTxtRecords.Add(new DnsTxtRecordInfo { Values = { dnsValue } });
                await existing.UpdateAsync(existing.Data);
            }

            // Propagation polling
            var propagationDeadline = DateTime.UtcNow.AddMinutes(propagationMinutes);
            bool propagated = false;
            while (DateTime.UtcNow < propagationDeadline)
            {
                try
                {
                    var q = await lookup.QueryAsync($"_acme-challenge.{domain}", QueryType.TXT);
                    if (q.Answers.TxtRecords().Any(a => a.Text.Any(t => t == dnsValue)))
                    {
                        propagated = true;
                        break;
                    }
                }
                catch { /* ignore transient */ }
                await Task.Delay(TimeSpan.FromSeconds(5));
            }
            if (!propagated)
                return new ApiError { Code = "dns_propagation_timeout", Message = $"TXT propagation timeout for {domain}" };

            // Ask ACME to validate this specific challenge
            await dnsCtx.Validate();

            // Poll challenge status
            var challengeDeadline = DateTime.UtcNow.AddMinutes(challengeMinutes);
            var challengeRes = await dnsCtx.Resource();
            while (DateTime.UtcNow < challengeDeadline &&
                   (challengeRes.Status == ChallengeStatus.Pending || challengeRes.Status == ChallengeStatus.Processing))
            {
                await Task.Delay(TimeSpan.FromSeconds(4));
                challengeRes = await dnsCtx.Resource();
            }

            if (challengeRes.Status != ChallengeStatus.Valid)
                return new ApiError { Code = "challenge_invalid", Message = $"Challenge invalid for {domain}. Status={challengeRes.Status}" };

            // Optional cleanup
            if (cleanup)
            {
                try
                {
                    var got = await txtCollection.GetAsync(recordRelativeName);
                    var toDelete = got.Value;
                    if (toDelete != null)
                        await toDelete.DeleteAsync(Azure.WaitUntil.Completed);
                }
                catch
                {
                    // non-fatal
                }
            }
        }

        return null;
    }

    private static string ComputeRecordRelativeName(string domain, string zone)
    {
        if (string.Equals(domain, zone, StringComparison.OrdinalIgnoreCase))
            return "_acme-challenge";
        if (domain.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase))
        {
            var left = domain[..^(zone.Length + 1)];
            return $"_acme-challenge.{left}";
        }
        return "_acme-challenge." + domain;
    }
}