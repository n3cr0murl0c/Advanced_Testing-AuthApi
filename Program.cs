using AuthApi.Data;
using AuthApi.Infrastructure.Security;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// ── Database ──────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=auth.db")
);

// ── ASP.NET Core Identity ─────────────────────────────────────────────────────
builder
    .Services.AddIdentity<ApplicationUser, IdentityRole>(opt =>
    {
        // Password policy
        opt.Password.RequireDigit = true;
        opt.Password.RequiredLength = 8;
        opt.Password.RequireUppercase = false;
        opt.Password.RequireNonAlphanumeric = false;

        // Lockout
        opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        opt.Lockout.MaxFailedAccessAttempts = 5;

        // User
        opt.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ── ECDSA Key Provider (singleton — holds the ECDsa instance) ─────────────────
builder.Services.AddSingleton<EcdsaKeyProvider>();

// ── Token Blacklist (singleton — in-memory, swap for Redis in prod) ───────────
builder.Services.AddSingleton<TokenBlacklist>();

// ── Token Service ─────────────────────────────────────────────────────────────
builder.Services.AddScoped<TokenService>();

// ── JWT Bearer Authentication ─────────────────────────────────────────────────
builder
    .Services.AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(opt =>
    {
        var jwtConfig = builder.Configuration.GetSection("Jwt");

        opt.TokenValidationParameters = new TokenValidationParameters
        {
            // ── Signature ──────────────────────────────────────────────────
            // IssuerSigningKey is set dynamically below via events so we can
            // pull it from the singleton without a service-locator anti-pattern.
            ValidateIssuerSigningKey = true,

            // ── Issuer / Audience ──────────────────────────────────────────
            ValidateIssuer = true,
            ValidIssuer = jwtConfig["Issuer"],

            ValidateAudience = true,
            ValidAudience = jwtConfig["Audience"],

            // ── Lifetime ───────────────────────────────────────────────────
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),

            // Map sub claim → ClaimTypes.NameIdentifier
            NameClaimType = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub,
        };

        opt.Events = new JwtBearerEvents
        {
            // Single handler: inject ECDSA public key + enforce blacklist
            OnTokenValidated = async ctx =>
            {
                var keyProvider =
                    ctx.HttpContext.RequestServices.GetRequiredService<EcdsaKeyProvider>();
                var blacklist =
                    ctx.HttpContext.RequestServices.GetRequiredService<TokenBlacklist>();

                // Ensure the public key is set for subsequent validations
                ctx.Options.TokenValidationParameters.IssuerSigningKey =
                    keyProvider.PublicSecurityKey;

                // Reject revoked tokens (jti in blacklist → logout was called)
                var jti = ctx
                    .Principal?.FindFirst(
                        System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti
                    )
                    ?.Value;

                if (jti is not null && blacklist.IsRevoked(jti))
                    ctx.Fail("Token has been revoked.");

                await Task.CompletedTask;
            },
        };
    });

builder.Services.AddAuthorization();

// ── MVC + custom validation error shape ───────────────────────────────────────
// Without this factory, absent/invalid fields return the default ProblemDetails
// format instead of the API's ErrorResponse shape.
// [Required] + required keyword both funnel through InvalidModelStateResponseFactory.
builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(opt =>
    {
        opt.InvalidModelStateResponseFactory = ctx =>
            new BadRequestObjectResult(new ErrorResponse(
                "VALIDATION_FAILED",
                string.Join("; ", ctx.ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage))));
    });

// ── OpenAPI / Scalar ──────────────────────────────────────────────────────────
builder.Services.AddOpenApi();

// ─────────────────────────────────────────────────────────────────────────────
var app = builder.Build();

// ── Database init + seed roles ────────────────────────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    await db.Database.MigrateAsync();

    foreach (var role in new[] { "Admin", "User" })
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
}

// ── Middleware pipeline ───────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Expose Program for integration tests
public partial class Program { }
