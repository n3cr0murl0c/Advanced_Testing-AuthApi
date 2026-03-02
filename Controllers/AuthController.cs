using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthApi.Data;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("auth")]
[Produces("application/json")]
public sealed class AuthController(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    TokenService tokenService,
    TokenBlacklist blacklist,
    ILogger<AuthController> logger
) : ControllerBase
{
    // ── POST /auth/register ───────────────────────────────────────────────────

    /// <summary>Register a new user account.</summary>
    [HttpPost("register")]
    [ProducesResponseType(typeof(RegisterResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req)
    {
        // Check duplicate email
        if (await userManager.FindByEmailAsync(req.Email) is not null)
            return Conflict(new ErrorResponse("EMAIL_TAKEN", "Email is already registered."));

        // Check duplicate username
        if (await userManager.FindByNameAsync(req.Username) is not null)
            return Conflict(new ErrorResponse("USERNAME_TAKEN", "Username is already taken."));

        var user = new ApplicationUser
        {
            UserName = req.Username,
            Email = req.Email,
            DisplayName = req.DisplayName ?? req.Username,
            // EmailConfirmed = true in dev; in prod send confirmation email
            EmailConfirmed = true,
        };

        var result = await userManager.CreateAsync(user, req.Password);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description);
            return BadRequest(new ErrorResponse("VALIDATION_FAILED", string.Join("; ", errors)));
        }

        // Assign default role
        await userManager.AddToRoleAsync(user, "User");

        logger.LogInformation("New user registered: {UserId} ({Email})", user.Id, user.Email);

        return CreatedAtAction(
            nameof(Validate),
            new RegisterResponse(user.Id, user.Email!, user.UserName!)
        );
    }

    // ── POST /auth/login ──────────────────────────────────────────────────────

    /// <summary>Authenticate and receive a signed ES256 JWT.</summary>
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var user = await userManager.FindByEmailAsync(req.Email);
        if (user is null)
        {
            logger.LogWarning("Login attempt for unknown email: {Email}", req.Email);
            return Unauthorized(
                new ErrorResponse("INVALID_CREDENTIALS", "Email or password is incorrect.")
            );
        }

        // CheckPasswordSignInAsync handles lockout, password verification, etc.
        var result = await signInManager.CheckPasswordSignInAsync(
            user,
            req.Password,
            lockoutOnFailure: true
        );

        if (result.IsLockedOut)
            return Unauthorized(
                new ErrorResponse("ACCOUNT_LOCKED", "Account locked. Try again later.")
            );

        if (!result.Succeeded)
        {
            logger.LogWarning("Failed login for {Email}", req.Email);
            return Unauthorized(
                new ErrorResponse("INVALID_CREDENTIALS", "Email or password is incorrect.")
            );
        }

        var (token, expiresAt) = await tokenService.IssueTokenAsync(user);
        var expiresIn = (int)(expiresAt - DateTime.UtcNow).TotalSeconds;

        return Ok(new LoginResponse(token, "Bearer", expiresIn, expiresAt));
    }

    // ── GET /auth/validate ────────────────────────────────────────────────────

    /// <summary>
    /// Validate the Bearer token and return its decoded claims.
    /// The JWT Bearer middleware performs signature verification before this
    /// action is reached; if the token is invalid the middleware returns 401.
    /// </summary>
    [HttpGet("validate")]
    [Authorize]
    [ProducesResponseType(typeof(ValidateResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Validate()
    {
        var claims = User.Claims.ToList();
        var sub = claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value;
        var email = claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value;
        var username = claims.First(c => c.Type == ClaimTypes.Name).Value;
        var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
        var iat = long.Parse(
            claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat)?.Value ?? "0"
        );
        var exp = long.Parse(
            claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value ?? "0"
        );

        return Ok(new ValidateResponse(sub, email, username, roles, iat, exp));
    }

    // ── POST /auth/logout ─────────────────────────────────────────────────────

    /// <summary>
    /// Revoke the current token by adding its jti to the blacklist.
    /// Future requests with the same token will be rejected by a custom event handler.
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Logout()
    {
        var jti = User.FindFirstValue(JwtRegisteredClaimNames.Jti);
        var expStr = User.FindFirstValue(JwtRegisteredClaimNames.Exp);

        if (jti is null)
            return BadRequest(
                new ErrorResponse("MISSING_JTI", "Token does not contain a jti claim.")
            );

        var exp = expStr is not null
            ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(expStr)).UtcDateTime
            : DateTime.UtcNow.AddHours(1);

        blacklist.Revoke(jti, exp);
        logger.LogInformation("Token {Jti} revoked (logout)", jti);

        return NoContent();
    }
}
