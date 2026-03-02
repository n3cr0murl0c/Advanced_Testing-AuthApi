using System.Security.Cryptography;
using AuthApi.Infrastructure.Security;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthApi.Tests;

/// <summary>
/// Unit tests for <see cref="EcdsaKeyProvider"/>.
///
/// Black-box tests (BN) verify observable behavior through the public API.
/// White-box tests (CB) drive specific internal branches via code inspection.
/// </summary>
public sealed class EcdsaKeyProviderTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

    public EcdsaKeyProviderTests() => Directory.CreateDirectory(_tempDir);

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort cleanup */ }
    }

    private IConfiguration BuildConfig(string keyPath) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Jwt:EcdsaKeyPath"] = keyPath })
            .Build();

    // ── BN-01: Key generated when PEM does not exist ──────────────────────────

    /// <summary>
    /// TECHNIQUE: Equivalence partition — file absent class.
    /// When no PEM file exists at the configured path the provider must generate
    /// a new key pair and persist a PKCS#8 PEM file at that path.
    /// </summary>
    [Fact]
    public void Constructor_WhenKeyFileAbsent_GeneratesAndPersistsPem()
    {
        var keyPath = Path.Combine(_tempDir, "new-key.pem");

        using var provider = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);

        File.Exists(keyPath).Should().BeTrue("PEM file must be written on first run");
        File.ReadAllText(keyPath).Should().Contain("PRIVATE KEY", "file must be PKCS#8 PEM");
    }

    // ── BN-02: Persisted key reloaded on second instantiation ────────────────

    /// <summary>
    /// TECHNIQUE: Equivalence partition — file present class.
    /// A second provider instance must load the same key so tokens issued across
    /// restarts remain verifiable.
    /// </summary>
    [Fact]
    public void Constructor_WhenKeyFileExists_LoadsSameKey()
    {
        var keyPath = Path.Combine(_tempDir, "reload-key.pem");

        // First boot: generate
        using var p1 = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);
        var pub1 = ExportPublicBytes(p1.PublicSecurityKey);

        // Second boot: reload
        using var p2 = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);
        var pub2 = ExportPublicBytes(p2.PublicSecurityKey);

        pub1.Should().Equal(pub2, "reloaded public key must match the originally generated key");
    }

    // ── BN-03: SigningCredentials algorithm is ES256 ──────────────────────────

    /// <summary>
    /// TECHNIQUE: Equivalence partition — algorithm correctness.
    /// Issuing tokens with a wrong algorithm (e.g., RS256) would break clients.
    /// </summary>
    [Fact]
    public void SigningCredentials_AlgorithmIsES256()
    {
        var keyPath = Path.Combine(_tempDir, "alg-key.pem");
        using var provider = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);

        provider.SigningCredentials.Algorithm
            .Should().Be(SecurityAlgorithms.EcdsaSha256, "ES256 is the only accepted algorithm");
    }

    // ── BN-04: PublicSecurityKey does NOT contain private key material ────────

    /// <summary>
    /// TECHNIQUE: Boundary / security check.
    /// The JWKS endpoint must never expose the private key scalar (d).
    /// </summary>
    [Fact]
    public void PublicSecurityKey_DoesNotContainPrivateKeyMaterial()
    {
        var keyPath = Path.Combine(_tempDir, "pub-only.pem");
        using var provider = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);

        var ecKey = provider.PublicSecurityKey.ECDsa;
        var action = () => ecKey.ExportParameters(includePrivateParameters: true);

        // Exporting private params from a public-only ECDsa must throw
        action.Should().Throw<CryptographicException>(
            "public key instance must not hold private key material");
    }

    // ── BN-05: Generated key is P-256 ────────────────────────────────────────

    /// <summary>
    /// TECHNIQUE: Equivalence partition — curve correctness.
    /// ES256 mandates P-256 (secp256r1). P-384 or P-521 would produce ES384/ES512.
    /// </summary>
    [Fact]
    public void GeneratedKey_CurveIsP256()
    {
        var keyPath = Path.Combine(_tempDir, "curve-key.pem");
        using var provider = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);

        var @params = provider.PublicSecurityKey.ECDsa.ExportParameters(includePrivateParameters: false);
        @params.Curve.Oid.FriendlyName.Should().BeOneOf("ECDSA_P256", "nistP256", "prime256v1");
    }

    // ── CB-01 (White-box): Branch — file exists path sets same kid ────────────

    /// <summary>
    /// TECHNIQUE: Branch coverage — D1 true (file present) and false (file absent).
    /// Both branches must produce a key with kid = "ecdsa-1".
    /// </summary>
    [Theory]
    [InlineData(true)]   // file present branch
    [InlineData(false)]  // file absent branch
    public void KeyId_IsEcdsaDash1_InBothBranches(bool preCreateKey)
    {
        var keyPath = Path.Combine(_tempDir, $"kid-{preCreateKey}-key.pem");

        if (preCreateKey)
        {
            // Pre-create a valid PEM so the load-from-file branch executes
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(keyPath, ecdsa.ExportPkcs8PrivateKeyPem());
        }

        using var provider = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);

        provider.SigningCredentials.Key.KeyId.Should().Be("ecdsa-1");
        provider.PublicSecurityKey.KeyId.Should().Be("ecdsa-1");
    }

    // ── CB-02 (White-box): Sign + verify round-trip with generated key ────────

    /// <summary>
    /// TECHNIQUE: Path coverage — end-to-end signature path through EcdsaKeyProvider.
    /// A payload signed with the private key must verify with the public key.
    /// </summary>
    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        var keyPath = Path.Combine(_tempDir, "rt-key.pem");
        using var provider = new EcdsaKeyProvider(BuildConfig(keyPath), NullLogger<EcdsaKeyProvider>.Instance);

        var payload = System.Text.Encoding.UTF8.GetBytes("test-payload");

        // Sign with private key (via SigningCredentials.Key)
        var privateKey = ((ECDsaSecurityKey)provider.SigningCredentials.Key).ECDsa;
        var signature  = privateKey.SignData(payload, HashAlgorithmName.SHA256);

        // Verify with public key
        var publicKey = provider.PublicSecurityKey.ECDsa;
        publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256)
            .Should().BeTrue("signature created with private key must verify with matching public key");
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static byte[] ExportPublicBytes(ECDsaSecurityKey key)
    {
        var p = key.ECDsa.ExportParameters(includePrivateParameters: false);
        return [.. p.Q.X!, .. p.Q.Y!];
    }
}
