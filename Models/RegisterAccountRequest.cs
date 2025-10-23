namespace Keyvault_cert_issueance.Models;

public sealed class RegisterAccountRequest
{
    public string? Email { get; set; }
    public bool? UseStaging { get; set; }
}