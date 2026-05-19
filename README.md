# Qudo Portal Backend

Spring Boot JSON API that backs the [Qudo Portal Frontend](../qudo-portal-frontend). Self-contained — no microservice fan-out. The new v2 portal is one React SPA + this one Spring Boot app.

## What it serves

| Surface | Path | Auth (when enabled) |
| --- | --- | --- |
| Health | `/actuator/health` | public |
| Current user | `/api/v1/me` | public; returns the persisted user when signed in, `{authenticated: false}` otherwise |
| Demo request | `POST /api/v1/public/demo/request` | public |
| Demo signing pubkey | `GET /api/v1/public/demo/signing-pubkey` | public |
| TLS scanner | `POST /api/v1/scan` | public |
| Sandboxes | `/api/v1/sandbox/**` | **signed in** when `app.auth.enabled=true` |
| Downloads (future) | `/api/v1/downloads/**` | **signed in** |
| Google OAuth start | `/oauth2/authorization/google` | public |
| Logout | `POST /api/v1/logout` | signed in |

The portal starts in **public mode** by default. Flip `APP_AUTH_ENABLED=true` (with Google credentials set) to turn on Google OAuth2 — sandbox + downloads routes become protected, and successful logins are written to Postgres.

## Persistence

The BE uses Postgres for durable state. Schema is managed by Flyway:

- `V1__create_users_table.sql` — portal users (one row per Google account)

JPA is configured with `ddl-auto: validate` — Flyway owns the schema, JPA only verifies that the entities match.

### Local Postgres in 30 seconds

```bash
docker compose up -d        # brings up Postgres 16 on localhost:5432
mvn spring-boot:run         # BE runs migrations on startup, then serves traffic
docker compose down -v      # stop AND wipe data when you're done
```

The default credentials (`qudo` / `qudo_local_dev`, db `qudo_portal`) match `application.yml`'s defaults so no env vars are needed for local dev.

For a different DB target, override:

```bash
export DB_URL=jdbc:postgresql://my-prod-host:5432/qudo_portal
export DB_USERNAME=...
export DB_PASSWORD=...
```

## Qudo JNI setup

The backend depends on a locally-installed `com.qudo:qudo-jni-crypto:1.0.0` artifact that ships under `libs/`. Install it into your local Maven repo once:

```bash
mvn install:install-file \
  -Dfile=libs/qudo-jni-crypto-1.0.0.jar \
  -DpomFile=libs/qudo-jni-crypto-1.0.0.pom \
  -DgroupId=com.qudo -DartifactId=qudo-jni-crypto -Dversion=1.0.0 -Dpackaging=jar
```

The native library (`libqudo_jni_crypto.{dylib,so}`) must be on `java.library.path` at runtime. The Spring Boot Maven plugin is wired to pass `-Djava.library.path=${qudo.native.lib.path}` for you — the default points at `../qudo-jni-crypto/build`. Override:

```bash
mvn -Dqudo.native.lib.path=/absolute/path/to/qudo-jni-crypto/build spring-boot:run
```

## Run locally

```bash
docker compose up -d
mvn spring-boot:run
```

Then start the frontend in the sibling `qudo-portal-frontend` repo (proxies `/api/**` to port 8093).

## Build for prod

```bash
mvn package
java -Djava.library.path=/path/to/qudo/lib -jar target/qudo-portal-backend-1.0.0.jar
```

Or via Docker (requires the `qudo-pqc-runtime:latest` base image with the native lib baked in):

```bash
docker build -t qudo-portal-backend:1.0.0 .
docker run -p 8093:8093 \
  -e DB_URL=jdbc:postgresql://db:5432/qudo_portal \
  -e DB_USERNAME=... -e DB_PASSWORD=... \
  -e FRONTEND_ORIGIN=https://qudo.zenv.ai \
  qudo-portal-backend:1.0.0
```

## Enabling Google OAuth2 sign-in

Auth is off by default (`app.auth.enabled=false`). To turn it on:

1. **Create an OAuth 2.0 Client ID** in [Google Cloud Console](https://console.cloud.google.com/apis/credentials):
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:8093/login/oauth2/code/google` (and the prod equivalent)
   - Authorized JS origins: `http://localhost:5173` (and prod)

2. **Export the credentials + flip the switch**:

   ```bash
   export APP_AUTH_ENABLED=true
   export GOOGLE_CLIENT_ID=...
   export GOOGLE_CLIENT_SECRET=...
   export FRONTEND_ORIGIN=http://localhost:5173
   mvn spring-boot:run
   ```

3. **Verify**:
   - Hit `http://localhost:8093/api/v1/sandbox/vpn/health` — should return `401 Unauthorized`.
   - Hit `http://localhost:8093/oauth2/authorization/google` — should redirect to Google.
   - After consent, you'll land back on the SPA and a row will appear in the `users` table:
     ```bash
     docker compose exec db psql -U qudo -d qudo_portal -c "select id, email, login_count, last_login_at from users"
     ```

When `APP_AUTH_ENABLED` is unset/false the OAuth2 placeholder credentials (`client-id: disabled`) are loaded by Spring's auto-config but never exercised — the SecurityFilterChain returns a permit-all chain.

## Layout

```
src/main/java/com/pqc/
├── PortalApplication.java          # @SpringBootApplication entry point
├── config/
│   └── SecurityConfig.java         # conditional OAuth2 + CORS, switches on app.auth.enabled
├── controller/
│   ├── AuthController.java         # /api/v1/me (DB-backed when signed in)
│   ├── DemoRequestController.java  # /api/v1/public/demo/*
│   └── ScannerController.java      # /api/v1/scan TLS posture scanner
├── user/
│   ├── User.java                   # JPA entity
│   ├── UserRepository.java         # JpaRepository
│   └── UserService.java            # upsertFromOAuth + lookup
├── sandbox/
│   ├── vpn/                        # ML-KEM-1024 + ML-DSA-65 VPN sandbox
│   ├── exchange/, dapp/, nft/, iot/, blockchain/, wallet/, defi/
│   ├── restapi/                    # PQC JWT
│   ├── signing/, ca/, email/, kms/, grpc/
└── common/
    └── QudoCryptoService.java      # Spring bean wrapping the Qudo JNI provider

src/main/resources/
├── application.yml                 # config + Postgres + conditional OAuth2
└── db/migration/
    └── V1__create_users_table.sql  # Flyway baseline
```

Future migrations land in `db/migration` as `V2__*.sql`, `V3__*.sql`, etc.
