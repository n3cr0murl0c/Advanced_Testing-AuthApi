using AuthApi.Services;
using FluentAssertions;
using Xunit;

namespace AuthApi.Tests;

/// <summary>
/// Unit tests for <see cref="TokenBlacklist"/>.
/// Validates the revoke/check/purge cycle — this is the core of logout security.
/// </summary>
public sealed class TokenBlacklistTests
{
    private readonly TokenBlacklist _sut = new();

    // ── BN-15: Active (non-revoked) token is not in blacklist ────────────────

    [Fact]
    public void IsRevoked_ReturnsFalse_ForUnknownJti()
    {
        _sut.IsRevoked("unknown-jti").Should().BeFalse();
    }

    // ── BN-16: Revoked token is detected on next check ───────────────────────

    [Fact]
    public void Revoke_ThenIsRevoked_ReturnsTrue()
    {
        var jti = Guid.NewGuid().ToString();
        _sut.Revoke(jti, DateTime.UtcNow.AddHours(1));

        _sut.IsRevoked(jti).Should().BeTrue();
    }

    // ── CB-11 (White-box — DEF-03): Branch blacklist.has(token) true ─────────

    [Fact]
    public void IsRevoked_AfterRevoke_ReturnsTrueOnEverySubsequentCall()
    {
        var jti = Guid.NewGuid().ToString();
        _sut.Revoke(jti, DateTime.UtcNow.AddHours(1));

        // Must remain revoked on multiple checks (idempotent)
        _sut.IsRevoked(jti).Should().BeTrue();
        _sut.IsRevoked(jti).Should().BeTrue();
    }

    // ── CB: Purge removes expired entries, keeps active ones ─────────────────

    [Fact]
    public void Purge_RemovesExpiredEntries_KeepsActiveOnes()
    {
        var expiredJti = "expired-jti";
        var activeJti = "active-jti";

        _sut.Revoke(expiredJti, DateTime.UtcNow.AddSeconds(-1)); // already expired
        _sut.Revoke(activeJti, DateTime.UtcNow.AddHours(1)); // still valid

        _sut.Purge();

        _sut.IsRevoked(expiredJti).Should().BeFalse("expired entries must be purged");
        _sut.IsRevoked(activeJti).Should().BeTrue("active entries must survive purge");
    }

    // ── BN: Revoking same jti twice is idempotent ────────────────────────────

    [Fact]
    public void Revoke_SameJtiTwice_DoesNotThrow()
    {
        var jti = Guid.NewGuid().ToString();
        _sut.Revoke(jti, DateTime.UtcNow.AddHours(1));

        var act = () => _sut.Revoke(jti, DateTime.UtcNow.AddHours(2));
        act.Should().NotThrow();
        _sut.IsRevoked(jti).Should().BeTrue();
    }

    // ── BN: Thread-safety sanity (concurrent revokes must not throw) ─────────

    [Fact]
    public void Revoke_ConcurrentAccess_DoesNotThrow()
    {
        var jtis = Enumerable.Range(0, 100).Select(_ => Guid.NewGuid().ToString()).ToList();

        var act = () =>
            Parallel.ForEach(jtis, jti => _sut.Revoke(jti, DateTime.UtcNow.AddHours(1)));
        act.Should().NotThrow();

        jtis.All(_sut.IsRevoked).Should().BeTrue();
    }
}
