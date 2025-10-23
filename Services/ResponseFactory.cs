using Keyvault_cert_issueance.Models;

namespace Keyvault_cert_issueance.Services;

public class ResponseFactory
{
    public ApiError Error(string code, string message, params string[] details) =>
        new ApiError { Code = code, Message = message, Details = details.Length == 0 ? null : details };

    public ApiResponse<T> Success<T>(string correlationId, T data) =>
        new ApiResponse<T> { CorrelationId = correlationId, Data = data };

    public ApiResponse<T> Failure<T>(string correlationId, ApiError error) =>
        new ApiResponse<T> { CorrelationId = correlationId, Error = error };
}