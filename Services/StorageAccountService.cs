using System;
using System.IO;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace Keyvault_cert_issueance.Services;

public class StorageAccountService
{
    private readonly BlobServiceClient _blobService;
    private const string DefaultContainer = "acme-accounts";

    public StorageAccountService(DefaultAzureCredential credential)
    {
        var accountName = Environment.GetEnvironmentVariable("APP_STORAGE_ACCOUNT_NAME")
            ?? throw new InvalidOperationException("APP_STORAGE_ACCOUNT_NAME not set.");
        var endpoint = new Uri($"https://{accountName}.blob.core.windows.net/");
        _blobService = new BlobServiceClient(endpoint, credential);
    }

    private BlobContainerClient GetContainer()
    {
        var containerName = Environment.GetEnvironmentVariable("ACME_ACCOUNT_CONTAINER") ?? DefaultContainer;
        var container = _blobService.GetBlobContainerClient(containerName.ToLowerInvariant());
        container.CreateIfNotExists(PublicAccessType.None);
        return container;
    }

    public async Task<string?> ReadAccountKeyPemAsync(bool staging)
    {
        var container = GetContainer();
        var blob = container.GetBlobClient(staging ? "account-staging.pem" : "account-prod.pem");
        if (!await blob.ExistsAsync()) return null;
        var download = await blob.DownloadContentAsync();
        return download.Value.Content.ToString();
    }

    public async Task WriteAccountKeyPemAsync(bool staging, string pem)
    {
        var container = GetContainer();
        var blob = container.GetBlobClient(staging ? "account-staging.pem" : "account-prod.pem");
        using var ms = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(pem));
        await blob.UploadAsync(ms, overwrite: true);
    }
}