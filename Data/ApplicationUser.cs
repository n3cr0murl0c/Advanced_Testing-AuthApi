using Microsoft.AspNetCore.Identity;

namespace AuthApi.Data;

/// <summary>
/// Extends the default IdentityUser with domain-specific profile properties.
/// All Identity infrastructure (password hash, lockout, tokens, etc.) is inherited.
/// </summary>
public sealed class ApplicationUser : IdentityUser
{
    public string? DisplayName { get; set; }
    public DateTime CreatedAt  { get; set; } = DateTime.UtcNow;
}
