using Microsoft.Extensions.DependencyInjection;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Infrastructure;

public static class ServiceRegistrar
{
    public static IServiceCollection RegisterCertificateIssuanceServices(this IServiceCollection services)
    {
        services.AddSingleton<StorageAccountService>();
        services.AddSingleton<AcmeAccountService>();
        services.AddSingleton<DnsChallengeService>(); // Note: file name currently DnsChallengeService.cs (typo). Consider renaming.
        services.AddSingleton<KeyVaultService>();
        services.AddSingleton<CertificateOrderService>();
        services.AddSingleton<ResponseFactory>();
        return services;
    }
}