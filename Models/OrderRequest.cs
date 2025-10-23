using Azure.Identity;
using Azure.ResourceManager;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Azure.Storage.Blobs;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Infrastructure;
namespace Keyvault_cert_issueance.Models;

public sealed class OrderRequest
{
    public string? PrimaryDomain { get; set; }
    public string[]? AdditionalNames { get; set; }
    public string? CertificateName { get; set; }
    public bool? UseStaging { get; set; }
    public bool? DryRun { get; set; }
    public bool? CleanupDns { get; set; }
}