# AGENTS.md — AuthApi Advanced Testing Project

## Project Overview

**System Under Test:** API REST de Autenticación con ASP.NET Core Identity, EF Core 10 (SQLite), JWT ES256 (ECDSA P-256).

**Academic Context:** Estudio Empírico Comparativo — Pruebas de Caja Negra vs. Caja Blanca. Maestría en Ingeniería en Software, Pruebas de Software Avanzadas.

## Project Structure

```
/
├── AGENTS.md                        # This file — change history and context
├── AuthApi.sln                      # Solution (main project + test project)
├── AuthApi.csproj                   # Main web API project (net10.0, Sdk.Web)
├── Program.cs                       # App bootstrap, DI, JWT Bearer config
├── Controllers/
│   ├── AuthController.cs            # POST /auth/register, login, logout; GET /auth/validate
│   └── JwksController.cs            # GET /.well-known/jwks.json
├── Services/
│   ├── TokenService.cs              # JWT ES256 issuance
│   └── TokenBlacklist.cs            # In-memory jti revocation store (ConcurrentDictionary)
├── Infrastructure/Security/
│   └── EcdsaKeyProvider.cs          # ECDSA P-256 key generation/load from PEM
├── Data/
│   ├── ApplicationDbContext.cs      # EF Core Identity DbContext
│   └── ApplicationUser.cs           # Extended IdentityUser (DisplayName)
├── Models/                          # DTOs: RegisterRequest/Response, LoginRequest/Response, etc.
├── Tests/
│   ├── AuthApi.Tests.csproj         # Test project (net10.0, Sdk — NOT Sdk.Web)
│   ├── EcdsaKeyProviderTests.cs     # 8 tests: BN-01..05, CB-01..02 (Theory + Facts)
│   ├── TokenServiceTests.cs         # 11 tests: BN-09..16 subset, CB-05..12
│   └── TokenBlacklistTests.cs       # 6 tests: BN-15..16 subset, CB-13..15
├── report/
│   ├── trabajo_grupal.tex           # Academic report (LaTeX)
│   ├── coverage.xml                 # dotnet-coverage raw output
│   ├── coverage-html/               # ReportGenerator HTML + Summary.txt + Cobertura.xml
│   └── testresults/                 # TRX files + Coverlet Cobertura XML
└── appsettings.json                 # JWT config: Issuer, Audience, ExpiryMinutes, EcdsaKeyPath
```

## Tech Stack

- **Runtime:** .NET 10.0.3
- **Framework:** ASP.NET Core 10 (Identity, EF Core, JWT Bearer)
- **Database:** SQLite (production), InMemory (tests)
- **Auth:** ECDSA P-256 / ES256 JWT tokens
- **Test Framework:** xUnit 2.9.3 + FluentAssertions 6.12.2
- **Coverage:** Coverlet 8.0.0 (XPlat Code Coverage) + ReportGenerator 5.5.2

## Commands

```bash
# Build
dotnet build AuthApi.sln

# Run tests
dotnet test AuthApi.sln --logger "console;verbosity=detailed"

# Run tests with coverage
dotnet test Tests/AuthApi.Tests.csproj \
  --collect:"XPlat Code Coverage" \
  --results-directory report/testresults \
  --logger "trx;LogFileName=results.trx"

# Generate HTML coverage report
reportgenerator \
  -reports:"report/testresults/**/coverage.cobertura.xml" \
  -targetdir:"report/coverage-html" \
  -reporttypes:"Html;TextSummary" \
  -assemblyfilters:"+AuthApi;-AuthApi.Tests"

# Run API
dotnet run --project AuthApi.csproj
```

## Test Results (2026-03-01)

| Suite                 | Tests  | PASS   | FAIL  | Duration     |
| --------------------- | ------ | ------ | ----- | ------------ |
| TokenBlacklistTests   | 6      | 6      | 0     | 148 ms       |
| EcdsaKeyProviderTests | 8      | 8      | 0     | 232 ms       |
| TokenServiceTests     | 11     | 11     | 0     | 1,851 ms     |
| **Total**             | **25** | **25** | **0** | **2,507 ms** |

## Coverage Results (Coverlet — modules under direct test)

| Module              | Line Coverage | Branch Coverage |
| ------------------- | ------------- | --------------- |
| EcdsaKeyProvider.cs | 97.4%         | 100%            |
| TokenService.cs     | 100%          | 100%            |
| TokenBlacklist.cs   | 100%          | 100%            |

## Known Defects

| ID     | Case  | Severity | Status                                                            |
| ------ | ----- | -------- | ----------------------------------------------------------------- |
| DEF-01 | BN-08 | Alta     | Open — missing `[Required]` on `RegisterRequest.Username`         |
| DEF-02 | BN-16 | Alta     | Open — blacklist check fires after JWT middleware validates token |

## Change Log

### [2026-03-01] — Initial Setup and Test Fixes

**Changes Made:**

1. `AuthApi.csproj`: Added `<Compile Remove="Tests\**" />` exclusion group to prevent the web SDK from glob-including test files, which caused duplicate assembly attribute errors and missing xunit/FluentAssertions references.
2. `Program.cs`: Added `using Scalar.AspNetCore;` — missing namespace for `MapScalarApiReference()` extension method.
3. `Tests/TokenBlacklistTests.cs`: Added `using Xunit;` and `using FluentAssertions;` — both were missing, causing `[Fact]` and `.Should()` to be unresolved.
4. `Tests/AuthApi.Tests.csproj`: Added `coverlet.collector` 8.0.0 for XPlat Code Coverage.
5. `report/trabajo_grupal.tex`: Updated all metrics sections with real measured data from test execution.

**Root Cause Analysis:**

- Tests were physically inside the main project folder (`Tests/` subfolder of root). `Microsoft.NET.Sdk.Web` glob-includes `**/*.cs` by default, so the main project compiled the test files and failed on missing xunit references.
- `TokenBlacklistTests.cs` was missing both `using` directives that the other two test files had.

**Impact:**

- Performance: neutral
- Functionality: tests now compile and run — 25/25 PASS
- Breaking Changes: no

**Affected Files:**

- `AuthApi.csproj`
- `Program.cs`
- `Tests/TokenBlacklistTests.cs`
- `Tests/AuthApi.Tests.csproj`
- `report/trabajo_grupal.tex`
