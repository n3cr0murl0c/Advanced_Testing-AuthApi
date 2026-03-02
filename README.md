# AuthApi — Advanced Testing

REST API de autenticación construida con **ASP.NET Core 10 + Identity + JWT ES256**, usada como sistema bajo prueba en un estudio empírico comparativo de pruebas de caja negra vs. caja blanca.

> **Contexto académico:** Maestría en Ingeniería en Software — Pruebas de Software Avanzadas, UNEMI.

---

## Stack

| Capa          | Tecnología                             |
| ------------- | -------------------------------------- |
| Runtime       | .NET 10.0                              |
| Framework     | ASP.NET Core 10 (Identity, EF Core 10) |
| Base de datos | SQLite (producción) · InMemory (tests) |
| Autenticación | JWT ES256 — ECDSA P-256 / SHA-256      |
| Tests         | xUnit 2.9.3 · FluentAssertions 6.12    |
| Cobertura     | Coverlet 8.0 · ReportGenerator 5.5     |

---

## Endpoints

| Método | Ruta                     | Descripción                                     |
| ------ | ------------------------ | ----------------------------------------------- |
| `POST` | `/auth/register`         | Registro de usuario (email, password, username) |
| `POST` | `/auth/login`            | Autenticación → JWT ES256                       |
| `GET`  | `/auth/validate`         | Valida el Bearer token y retorna sus claims     |
| `POST` | `/auth/logout`           | Revoca el token activo (blacklist por `jti`)    |
| `GET`  | `/.well-known/jwks.json` | Clave pública ECDSA en formato JWKS             |

---

## Requisitos

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- `reportgenerator` (opcional, para reporte HTML de cobertura)

```bash
dotnet tool install --global dotnet-reportgenerator-globaltool
```

---

## Inicio rápido

```bash
# Clonar
git clone https://github.com/n3cr0murl0c/Advanced_Testing-AuthApi.git
cd Advanced_Testing-AuthApi

# Restaurar dependencias y ejecutar migraciones + API
dotnet run --project AuthApi.csproj
```

La API arranca en `https://localhost:5001`. El explorador interactivo (Scalar) está disponible en desarrollo en `/scalar/v1`.

La clave ECDSA P-256 se genera automáticamente en `ecdsa-key.pem` al primer arranque.

---

## Configuración

`appsettings.json`:

```json
{
  "ConnectionStrings": {
    "Default": "Data Source=auth.db"
  },
  "Jwt": {
    "Issuer": "https://authapi.local",
    "Audience": "https://authapi.local/resources",
    "ExpiryMinutes": "60",
    "EcdsaKeyPath": "ecdsa-key.pem"
  }
}
```

---

## Ejecutar tests

```bash
# Suite completa
dotnet test AuthApi.sln --logger "console;verbosity=detailed"

# Con cobertura (Coverlet)
dotnet test Tests/AuthApi.Tests.csproj \
  --collect:"XPlat Code Coverage" \
  --results-directory report/testresults \
  --logger "trx;LogFileName=results.trx"

# Reporte HTML de cobertura
reportgenerator \
  -reports:"report/testresults/**/coverage.cobertura.xml" \
  -targetdir:"report/coverage-html" \
  -reporttypes:"Html;TextSummary" \
  -assemblyfilters:"+AuthApi;-AuthApi.Tests"
```

### Resultados (2026-03-01)

| Suite                   | Tests  | PASS   | FAIL  | Tiempo       |
| ----------------------- | ------ | ------ | ----- | ------------ |
| `TokenBlacklistTests`   | 6      | 6      | 0     | 148 ms       |
| `EcdsaKeyProviderTests` | 8      | 8      | 0     | 232 ms       |
| `TokenServiceTests`     | 11     | 11     | 0     | 1 851 ms     |
| **Total**               | **25** | **25** | **0** | **2 507 ms** |

### Cobertura (módulos bajo prueba directa)

| Módulo                | Líneas | Ramas |
| --------------------- | ------ | ----- |
| `EcdsaKeyProvider.cs` | 97.4 % | 100 % |
| `TokenService.cs`     | 100 %  | 100 % |
| `TokenBlacklist.cs`   | 100 %  | 100 % |

---

## Estructura del proyecto

```
/
├── AuthApi.sln
├── AuthApi.csproj              # Web API (net10.0, Sdk.Web)
├── Program.cs                  # Bootstrap, DI, JWT Bearer pipeline
├── Controllers/
│   ├── AuthController.cs       # Register · Login · Validate · Logout
│   └── JwksController.cs       # /.well-known/jwks.json
├── Services/
│   ├── TokenService.cs         # Emisión de JWT ES256
│   └── TokenBlacklist.cs       # Revocación en memoria (ConcurrentDictionary)
├── Infrastructure/Security/
│   └── EcdsaKeyProvider.cs     # Generación/carga de clave ECDSA P-256
├── Data/
│   ├── ApplicationDbContext.cs
│   └── ApplicationUser.cs      # IdentityUser extendido (DisplayName)
├── Models/
│   └── AuthDtos.cs             # DTOs: RegisterRequest/Response, LoginRequest/Response…
├── Tests/
│   ├── AuthApi.Tests.csproj
│   ├── EcdsaKeyProviderTests.cs
│   ├── TokenServiceTests.cs
│   └── TokenBlacklistTests.cs
└── report/
    ├── trabajo_grupal.tex       # Informe académico (LaTeX)
    ├── coverage-html/           # Reporte HTML de cobertura
    └── testresults/             # TRX + Cobertura XML
```

---

## Defectos conocidos

| ID     | Endpoint              | Descripción                                                                                                                                                | Severidad | Estado        |
| ------ | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------- |
| DEF-01 | `POST /auth/register` | Username omitido retornaba HTTP 201 en lugar de 400 — `RegisterRequest` era un positional record; el model binder asignaba `null` sin activar `[Required]` | Alta      | **Corregido** |
| DEF-02 | `GET /auth/validate`  | Token revocado post-logout sigue siendo aceptado — `ctx.Fail()` en `OnTokenValidated` no garantiza corte del pipeline. Corregido con middleware inline entre `UseAuthentication()` y `UseAuthorization()` | Alta      | **Corregido** |

---

## Licencia

MIT — ver [LICENSE](LICENSE).
