using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Infrastructure.Security;

/// <summary>
/// Manages the ECDSA P-256 key pair used to sign and verify JWT tokens.
///
/// Strategy:
///   1. On startup, look for a PEM file at the path configured in
///      "Jwt:EcdsaKeyPath" (defaults to "ecdsa-key.pem" beside the binary).
///   2. If found, load the private key from it.
///   3. If not found, generate a new ephemeral key AND persist it so restarts
///      don't invalidate already-issued tokens (important for dev; in prod you
///      would inject this via a secret store).
///
/// Signing algorithm: ES256  (ECDSA over P-256 with SHA-256)
/// </summary>
public sealed class EcdsaKeyProvider : IDisposable
{
    private readonly ECDsa _ecdsa;

    public EcdsaKeyProvider(IConfiguration config, ILogger<EcdsaKeyProvider> logger)
    {
        var keyPath = config["Jwt:EcdsaKeyPath"] ?? "ecdsa-key.pem";

        if (File.Exists(keyPath))
        {
            logger.LogInformation("Loading ECDSA private key from {Path}", keyPath);
            _ecdsa = LoadFromPem(keyPath);
        }
        else
        {
            logger.LogWarning(
                "ECDSA key not found at {Path} — generating ephemeral key and persisting it.", keyPath);
            _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            PersistToPem(keyPath, _ecdsa);
        }

        // Expose the public signing credentials used by AddJwtBearer validation
        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(_ecdsa) { KeyId = "ecdsa-1" },
            SecurityAlgorithms.EcdsaSha256);

        // Expose the public key only for the JWKS endpoint
        PublicSecurityKey = BuildPublicKey(_ecdsa);
    }

    /// <summary>Used when issuing tokens (needs private key).</summary>
    public SigningCredentials SigningCredentials { get; }

    /// <summary>Used for the /.well-known/jwks.json endpoint (public key only).</summary>
    public ECDsaSecurityKey PublicSecurityKey { get; }

    // ── Private helpers ─────────────────────────────────────────────────────

    private static ECDsa LoadFromPem(string path)
    {
        var pem = File.ReadAllText(path);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }

    private static void PersistToPem(string path, ECDsa ecdsa)
    {
        // Export private key as PKCS#8 PEM
        var pem = ecdsa.ExportPkcs8PrivateKeyPem();
        File.WriteAllText(path, pem);
        // Restrict file permissions on Unix
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static ECDsaSecurityKey BuildPublicKey(ECDsa privateKey)
    {
        // Clone into a new ECDsa instance that holds ONLY the public key
        var pubEcdsa = ECDsa.Create();
        pubEcdsa.ImportParameters(privateKey.ExportParameters(includePrivateParameters: false));
        return new ECDsaSecurityKey(pubEcdsa) { KeyId = "ecdsa-1" };
    }

    public void Dispose() => _ecdsa.Dispose();
}
