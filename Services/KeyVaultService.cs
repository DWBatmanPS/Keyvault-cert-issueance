using System;
using System.Linq;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Keyvault_cert_issueance.Models;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;

namespace Keyvault_cert_issueance.Services;

public class KeyVaultService
{
    private readonly ResponseFactory _responses;
    private readonly DefaultAzureCredential _credential;

    public KeyVaultService(ResponseFactory responses, DefaultAzureCredential credential)
    {
        _responses = responses;
        _credential = credential;
    }

    private (CertificateClient certClient, SecretClient secretClient) BuildClients(string keyVaultName)
    {
        var uri = new Uri($"https://{keyVaultName}.vault.azure.net/");
        return (new CertificateClient(uri, _credential), new SecretClient(uri, _credential));
    }

    public async Task<(CertificateMetadata? meta, ApiError? error)> ImportCertificateVersionAsync(
        string keyVaultName,
        string certificateName,
        byte[] pfxBytes,
        string? password,
        string[] domains,
        bool renewed,
        bool leafOnly = false)
    {
        try
            {
                var (certClient, _) = BuildClients(keyVaultName);
                var options = new ImportCertificateOptions(certificateName, pfxBytes)
                {
                    Password = password
                };
                options.Tags["sanList"] = string.Join(",", domains);
                if (renewed) options.Tags["renewed"] = "true";
                    
                                                    
                if (leafOnly) options.Tags["leafOnly"] = "true";

                var imported = await certClient.ImportCertificateAsync(options);
                var x509 = new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.Exportable);

                var meta = new CertificateMetadata
                {
                    CertificateName = certificateName,
                    Version = imported.Value.Properties.Version,
                    NotBefore = x509.NotBefore,
                    NotAfter = x509.NotAfter,
                    Domains = domains,
                    Renewed = renewed
                };
                return (meta, null);
            }
            catch (Exception ex)
            {
                return (null, _responses.Error("kv_import_error", "Failed importing certificate.", ex.Message));
            }
        }

    public async Task<(CertificateMetadata? meta, ApiError? error)> GetCurrentCertificateAsync(
        string keyVaultName,
        string certificateName)
    {
        try
        {
            var (certClient, secretClient) = BuildClients(keyVaultName);
            KeyVaultCertificateWithPolicy cert = await certClient.GetCertificateAsync(certificateName);
            // The secret holds PFX/Base64 maybe; we only need dates + SANs.
            var props = cert.Properties;
            var policy = cert.Policy;
            var notBefore = props.NotBefore ?? DateTimeOffset.MinValue;
            var notAfter = props.ExpiresOn ?? DateTimeOffset.MinValue;

            string[] domains;
            if (props.Tags.TryGetValue("sanList", out var san))
                domains = san.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            else if (policy?.SubjectAlternativeNames?.DnsNames?.Count > 0)
                domains = policy.SubjectAlternativeNames.DnsNames.ToArray();
            else
                domains = Array.Empty<string>();

            var meta = new CertificateMetadata
            {
                CertificateName = certificateName,
                Version = props.Version,
                NotBefore = notBefore,
                NotAfter = notAfter,
                Domains = domains,
                Renewed = false
            };
            return (meta, null);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return (null, _responses.Error("kv_not_found", "Certificate not found.", ex.Message));
        }
        catch (Exception ex)
        {
            return (null, _responses.Error("kv_get_error", "Failed retrieving certificate.", ex.Message));
        }
    }
}