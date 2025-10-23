using System;

namespace Keyvault_cert_issueance.Models;

public sealed class CertificateMetadata
{
    public string CertificateName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public string[] Domains { get; set; } = Array.Empty<string>();
    public bool Renewed { get; set; }
}