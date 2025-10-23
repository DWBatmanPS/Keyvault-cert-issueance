using System.Text.Json.Serialization;

namespace Keyvault_cert_issueance.Models;

public sealed class ApiResponse<T>
{
    public string CorrelationId { get; set; } = string.Empty;
    public T? Data { get; set; }
    public ApiError? Error { get; set; }

    [JsonIgnore]
    public bool HasError => Error != null;
}