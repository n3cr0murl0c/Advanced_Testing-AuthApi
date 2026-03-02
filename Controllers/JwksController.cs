using AuthApi.Infrastructure.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Controllers;

/// <summary>
/// Exposes the ECDSA public key in JSON Web Key Set format.
/// Clients and resource servers can fetch this endpoint to verify tokens
/// without ever seeing the private key.
///
/// GET /.well-known/jwks.json
/// </summary>
[ApiController]
[Route(".well-known")]
public sealed class JwksController(EcdsaKeyProvider keyProvider) : ControllerBase
{
    [HttpGet("jwks.json")]
    [ResponseCache(Duration = 3600)] // clients may cache for 1 hour
    public IActionResult GetJwks()
    {
        var key = keyProvider.PublicSecurityKey;

        // Build the JWK representation of the EC public key
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        // Ensure only public fields are exposed — strip any private key material
        var publicJwk = new
        {
            kty = jwk.Kty,   // "EC"
            use = "sig",
            kid = jwk.Kid,   // "ecdsa-1"
            alg = "ES256",
            crv = jwk.Crv,   // "P-256"
            x   = jwk.X,     // base64url X coordinate
            y   = jwk.Y,     // base64url Y coordinate
            // intentionally omit "d" (private key scalar)
        };

        return Ok(new { keys = new[] { publicJwk } });
    }
}
