using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models;

// ── Register ─────────────────────────────────────────────────────────────────

public sealed class RegisterRequest
{
    // required (C# keyword): STJ throws JsonException if field is absent from JSON body.
    // [Required] (DataAnnotations): model validation catches null that slips through.
    // Both layers are needed: required blocks absent fields at deserialization,
    // [Required] blocks null values; together they guarantee a consistent 400
    // with the custom ErrorResponse shape via InvalidModelStateResponseFactory.
    [Required, EmailAddress]
    public required string Email { get; set; }

    [Required, StringLength(64, MinimumLength = 8)]
    public required string Password { get; set; }

    [Required, StringLength(30, MinimumLength = 3)]
    public required string Username { get; set; }

    public string? DisplayName { get; set; } = null;
}

public sealed record RegisterResponse(string UserId, string Email, string Username);

// ── Login ─────────────────────────────────────────────────────────────────────

public sealed record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required] string Password
);

public sealed record LoginResponse(
    string AccessToken,
    string TokenType,
    int ExpiresIn, // seconds
    DateTime ExpiresAt
);

// ── Validate ──────────────────────────────────────────────────────────────────

public sealed record ValidateResponse(
    string Sub,
    string Email,
    string Username,
    IEnumerable<string> Roles,
    long Iat,
    long Exp
);

// ── Errors ────────────────────────────────────────────────────────────────────

public sealed record ErrorResponse(string Code, string Message);
