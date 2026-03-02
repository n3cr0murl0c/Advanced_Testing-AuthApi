using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthApi.Data;
using AuthApi.Infrastructure.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

/// <summary>
/// Builds and signs JWT tokens using ECDSA ES256.
///
/// Token anatomy
/// ─────────────
/// Header  : { "alg": "ES256", "kid": "ecdsa-1", "typ": "JWT" }
/// Payload :
///   iss   → configured issuer (e.g. "https://authapi.local")
///   aud   → configured audience
///   sub   → user ID (Identity primary key)
///   jti   → unique token id (Guid) — enables revocation
///   iat   → issued-at (Unix epoch)
///   exp   → expiry (iat + ExpiryMinutes)
///   email, name, roles → standard + custom claims
/// Signature: ES256 (ECDSA P-256 / SHA-256, private key)
/// </summary>
public sealed class TokenService(
    IConfiguration config,
    EcdsaKeyProvider keyProvider,
    UserManager<ApplicationUser> userManager)
{
    private static readonly JwtSecurityTokenHandler _handler = new();

    public async Task<(string Token, DateTime Expiry)> IssueTokenAsync(ApplicationUser user)
    {
        var issuer   = config["Jwt:Issuer"]   ?? throw new InvalidOperationException("Jwt:Issuer not configured");
        var audience = config["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience not configured");
        var expiry   = int.Parse(config["Jwt:ExpiryMinutes"] ?? "60");

        // ── Build claims ─────────────────────────────────────────────────────
        var roles = await userManager.GetRolesAsync(user);
        var userClaims = await userManager.GetClaimsAsync(user);

        var claims = new List<Claim>
        {
            // Standard JWT registered claims
            new(JwtRegisteredClaimNames.Sub,   user.Id),
            new(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat,   DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                                               ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Email, user.Email!),

            // Application claims
            new(ClaimTypes.Name,               user.UserName!),
            new("display_name",                user.DisplayName ?? user.UserName!),
            new("email_verified",              user.EmailConfirmed.ToString().ToLower()),
        };

        // Roles as individual role claims (standard interop with [Authorize(Roles=...)])
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        // Any additional claims stored in AspNetUserClaims table
        claims.AddRange(userClaims);

        // ── Build token descriptor ────────────────────────────────────────────
        var expiresAt = DateTime.UtcNow.AddMinutes(expiry);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer             = issuer,
            Audience           = audience,
            Subject            = new ClaimsIdentity(claims),
            Expires            = expiresAt,
            IssuedAt           = DateTime.UtcNow,
            NotBefore          = DateTime.UtcNow,
            SigningCredentials = keyProvider.SigningCredentials,
        };

        var token = _handler.CreateToken(descriptor);
        return (_handler.WriteToken(token), expiresAt);
    }
}
