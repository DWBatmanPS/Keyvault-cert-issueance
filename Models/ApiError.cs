namespace Keyvault_cert_issueance.Models;

public sealed class ApiError
{
    public string Code { get; set; } = "internal_error";
    public string Message { get; set; } = string.Empty;
    public string[]? Details { get; set; }
}