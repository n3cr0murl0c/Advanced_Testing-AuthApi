using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthApi.Data;
using AuthApi.Infrastructure.Security;
using AuthApi.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthApi.Tests;

/// <summary>
/// Unit tests for <see cref="TokenService"/>.
/// Covers JWT structure, claims presence, issuer/audience, algorithm and signature.
/// </summary>
public sealed class TokenServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly EcdsaKeyProvider _keyProvider;
    private readonly TokenService _tokenService;
    private readonly ApplicationUser _user;
    private readonly UserManager<ApplicationUser> _userManager;

    public TokenServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDir);

        // ── Config ─────────────────────────────────────────────────────────
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Jwt:Issuer"] = "https://test.issuer",
                    ["Jwt:Audience"] = "https://test.audience",
                    ["Jwt:ExpiryMinutes"] = "30",
                    ["Jwt:EcdsaKeyPath"] = Path.Combine(_tempDir, "test.pem"),
                }
            )
            .Build();

        // ── Key provider ───────────────────────────────────────────────────
        _keyProvider = new EcdsaKeyProvider(config, NullLogger<EcdsaKeyProvider>.Instance);

        // ── In-memory Identity setup ───────────────────────────────────────
        var dbOpts = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var db = new ApplicationDbContext(dbOpts);

        var userStore = new UserStore<ApplicationUser>(db);
        _userManager = new UserManager<ApplicationUser>(
            userStore,
            Options.Create(
                new IdentityOptions
                {
                    Password =
                    {
                        RequireDigit = false,
                        RequiredLength = 1,
                        RequireUppercase = false,
                        RequireNonAlphanumeric = false,
                    },
                }
            ),
            new PasswordHasher<ApplicationUser>(),
            [],
            [],
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            null!,
            NullLogger<UserManager<ApplicationUser>>.Instance
        );

        // Seed a test user
        _user = new ApplicationUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = "testuser",
            Email = "test@example.com",
            DisplayName = "Test User",
            EmailConfirmed = true,
        };

        _userManager.CreateAsync(_user, "password").GetAwaiter().GetResult();

        _tokenService = new TokenService(config, _keyProvider, _userManager);
    }

    public void Dispose()
    {
        _userManager.Dispose();
        _keyProvider.Dispose();
        Directory.Delete(_tempDir, recursive: true);
    }

    // ── BN-09: Successful login produces non-empty token ─────────────────────

    [Fact]
    public async Task IssueToken_ReturnsNonEmptyToken()
    {
        var (token, expiry) = await _tokenService.IssueTokenAsync(_user);

        token.Should().NotBeNullOrWhiteSpace();
        expiry.Should().BeAfter(DateTime.UtcNow);
    }

    // ── BN-12: Token expiry matches configured minutes ────────────────────────

    [Fact]
    public async Task IssueToken_ExpiryIsConfiguredDuration()
    {
        var before = DateTime.UtcNow;
        var (_, expiry) = await _tokenService.IssueTokenAsync(_user);

        expiry.Should().BeCloseTo(before.AddMinutes(30), precision: TimeSpan.FromSeconds(5));
    }

    // ── BN-13: Token contains correct issuer ─────────────────────────────────

    [Fact]
    public async Task IssueToken_IssuerClaimIsCorrect()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var jwt = ParseToken(token);
        jwt.Issuer.Should().Be("https://test.issuer");
    }

    // ── BN: Token contains correct audience ──────────────────────────────────

    [Fact]
    public async Task IssueToken_AudienceClaimIsCorrect()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var jwt = ParseToken(token);
        jwt.Audiences.Should().Contain("https://test.audience");
    }

    // ── BN: Token algorithm header is ES256 ──────────────────────────────────

    [Fact]
    public async Task IssueToken_AlgorithmHeaderIsES256()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var jwt = ParseToken(token);
        jwt.Header.Alg.Should().Be("ES256");
    }

    // ── BN: Token contains sub claim equal to user ID ────────────────────────

    [Fact]
    public async Task IssueToken_SubClaimEqualsUserId()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var jwt = ParseToken(token);
        var sub = jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value;
        sub.Should().Be(_user.Id);
    }

    // ── BN: Token contains email claim ───────────────────────────────────────

    [Fact]
    public async Task IssueToken_ContainsEmailClaim()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var jwt = ParseToken(token);
        var email = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value;
        email.Should().Be("test@example.com");
    }

    // ── BN: Token contains unique jti ─────────────────────────────────────────

    [Fact]
    public async Task IssueToken_JtiIsUniquePerIssuance()
    {
        var (t1, _) = await _tokenService.IssueTokenAsync(_user);
        var (t2, _) = await _tokenService.IssueTokenAsync(_user);

        var jti1 = ParseToken(t1).Id;
        var jti2 = ParseToken(t2).Id;

        jti1.Should().NotBe(jti2, "each token must have a unique jti for revocation support");
    }

    // ── CB-02 (White-box): ES256 signature verifies with ECDSA public key ────

    [Fact]
    public async Task IssueToken_SignatureVerifiesWithEcdsaPublicKey()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var handler = new JwtSecurityTokenHandler();
        var validParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _keyProvider.PublicSecurityKey,
            ValidateIssuer = true,
            ValidIssuer = "https://test.issuer",
            ValidateAudience = true,
            ValidAudience = "https://test.audience",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };

        var act = () => handler.ValidateToken(token, validParams, out _);
        act.Should()
            .NotThrow(
                "a token signed with the private key must validate with the matching public key"
            );
    }

    // ── CB: Tampered token must NOT verify ────────────────────────────────────

    [Fact]
    public async Task IssueToken_TamperedSignatureFails()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        // Flip the last character of the signature segment
        var parts = token.Split('.');
        parts[2] = parts[2][..^1] + (parts[2][^1] == 'A' ? 'B' : 'A');
        var tampered = string.Join('.', parts);

        var handler = new JwtSecurityTokenHandler();
        var validParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _keyProvider.PublicSecurityKey,
            ValidIssuer = "https://test.issuer",
            ValidAudience = "https://test.audience",
            ValidateLifetime = false,
        };

        var act = () => handler.ValidateToken(tampered, validParams, out _);
        act.Should().Throw<SecurityTokenInvalidSignatureException>();
    }

    // ── CB: Wrong issuer must NOT verify ─────────────────────────────────────

    [Fact]
    public async Task IssueToken_WrongIssuerFails()
    {
        var (token, _) = await _tokenService.IssueTokenAsync(_user);

        var handler = new JwtSecurityTokenHandler();
        var validParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _keyProvider.PublicSecurityKey,
            ValidateIssuer = true,
            ValidIssuer = "https://wrong.issuer", // ← wrong
            ValidateAudience = false,
            ValidateLifetime = false,
        };

        var act = () => handler.ValidateToken(token, validParams, out _);
        act.Should().Throw<SecurityTokenInvalidIssuerException>();
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static JwtSecurityToken ParseToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        handler.CanReadToken(token).Should().BeTrue("string must be a valid JWT");
        return handler.ReadJwtToken(token);
    }
}
