using System.Collections.Concurrent;

namespace AuthApi.Services;

/// <summary>
/// Thread-safe in-memory blacklist keyed by JWT ID (jti claim).
///
/// In production, replace with a distributed store (Redis, SQL) with TTL
/// equal to the token's remaining lifetime. The jti approach avoids storing
/// full token strings.
/// </summary>
public sealed class TokenBlacklist
{
    // jti → expiry time (for future cleanup / TTL enforcement)
    private readonly ConcurrentDictionary<string, DateTime> _revoked = new();

    public void Revoke(string jti, DateTime expiry) =>
        _revoked[jti] = expiry;

    public bool IsRevoked(string jti) =>
        _revoked.ContainsKey(jti);

    /// <summary>
    /// Purge expired entries (call periodically via IHostedService or background job).
    /// </summary>
    public void Purge()
    {
        var now = DateTime.UtcNow;
        foreach (var (jti, expiry) in _revoked)
            if (expiry < now) _revoked.TryRemove(jti, out _);
    }
}
