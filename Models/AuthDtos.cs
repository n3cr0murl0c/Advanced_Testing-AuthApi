using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models;

// ── Register ─────────────────────────────────────────────────────────────────

public sealed record RegisterRequest(
    [Required, EmailAddress]  string Email,
    [Required, MinLength(8), MaxLength(64)] string Password,
    [Required, MinLength(3), MaxLength(30)] string Username,
    string? DisplayName = null
);

public sealed record RegisterResponse(
    string UserId,
    string Email,
    string Username
);

// ── Login ─────────────────────────────────────────────────────────────────────

public sealed record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required]               string Password
);

public sealed record LoginResponse(
    string AccessToken,
    string TokenType,
    int    ExpiresIn,   // seconds
    DateTime ExpiresAt
);

// ── Validate ──────────────────────────────────────────────────────────────────

public sealed record ValidateResponse(
    string Sub,
    string Email,
    string Username,
    IEnumerable<string> Roles,
    long   Iat,
    long   Exp
);

// ── Errors ────────────────────────────────────────────────────────────────────

public sealed record ErrorResponse(string Code, string Message);
