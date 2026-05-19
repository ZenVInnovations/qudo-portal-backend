# Qudo Portal Backend

Spring Boot JSON API that backs the [Qudo Portal Frontend](../qudo-portal-frontend). Self-contained — no microservice fan-out. The new v2 portal is one React SPA + this one Spring Boot app.

## What it serves

| Surface | Path | Auth |
| --- | --- | --- |
| Health | `/actuator/health` | public |
| Current user (stub) | `/api/v1/me` | public; always returns `{authenticated: false}` for now |
| Demo request | `POST /api/v1/public/demo/request` | public |
| Demo signing pubkey | `GET /api/v1/public/demo/signing-pubkey` | public |
| VPN sandbox | `/api/v1/sandbox/vpn/**` | public (will be gated once auth is wired) |

> **Auth deferred.** Google OAuth2 will be added later. Right now everything is publicly accessible. The `/api/v1/me` endpoint exists as a stub so the frontend's `AuthGuard` machinery stays in place — flip it back on by re-adding the security deps and config (see "Re-enabling Google OAuth2" below).

## One-time setup

The backend depends on a locally-installed `com.qudo:qudo-jni-crypto:1.0.0` artifact that ships under `libs/`. Install it into your local Maven repo once:

```bash
mvn install:install-file \
  -Dfile=libs/qudo-jni-crypto-1.0.0.jar \
  -DpomFile=libs/qudo-jni-crypto-1.0.0.pom \
  -DgroupId=com.qudo -DartifactId=qudo-jni-crypto -Dversion=1.0.0 -Dpackaging=jar
```

The native library (`libqudo_jni_crypto.{dylib,so}`) must be on `java.library.path` at runtime. The Spring Boot Maven plugin is wired to pass `-Djava.library.path=${qudo.native.lib.path}` for you — the default points at `../qudo-jni-crypto/build` (a sibling checkout of the qudo-jni-crypto repo). Override if your build directory lives elsewhere:

```bash
mvn -Dqudo.native.lib.path=/absolute/path/to/qudo-jni-crypto/build spring-boot:run
```

When running the packaged jar directly:

```bash
java -Djava.library.path=../qudo-jni-crypto/build -jar target/qudo-portal-backend-1.0.0.jar
```

The Docker image places the lib at `/app/lib` and the entrypoint already sets `-Djava.library.path=/app/lib`.

## Run locally

```bash
mvn spring-boot:run
```

Then start the frontend in the sibling `qudo-portal-frontend` repo. The frontend's Vite dev server proxies `/api/**` to this backend on port 8093.

## Build for prod

```bash
mvn package
java -jar target/qudo-portal-backend-1.0.0.jar
```

Or via Docker (requires the `qudo-pqc-runtime:latest` base image with the native lib baked in):

```bash
docker build -t qudo-portal-backend:1.0.0 .
docker run -p 8093:8093 \
  -e FRONTEND_ORIGIN=https://qudo.zenv.ai \
  qudo-portal-backend:1.0.0
```

## Re-enabling Google OAuth2

When ready to add sign-in back:

1. **`pom.xml`** — add back the two Spring Security starters:

   ```xml
   <dependency>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-security</artifactId>
   </dependency>
   <dependency>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-oauth2-client</artifactId>
   </dependency>
   ```

2. **`application.yml`** — uncomment the `spring.security.oauth2.client.registration.google` block.

3. **`SecurityConfig.java`** — restore from git history (was at `src/main/java/com/pqc/config/SecurityConfig.java`; recover with `git show <pre-strip-commit>:src/main/java/com/pqc/config/SecurityConfig.java`).

4. **`AuthController.java`** — re-inject `@AuthenticationPrincipal OAuth2User` and return its claims instead of the stub.

5. **Google Cloud Console** — create an OAuth 2.0 Web Application Client ID and set the env vars:

   ```bash
   export GOOGLE_CLIENT_ID=...
   export GOOGLE_CLIENT_SECRET=...
   export FRONTEND_ORIGIN=http://localhost:5173
   ```

   Authorized redirect URI: `http://localhost:8093/login/oauth2/code/google` (and the prod equivalent).

6. **Frontend** — restore the AuthGuard's check and the sign-in/sign-out buttons in `Navbar.tsx`.

## Layout

```
src/main/java/com/pqc/
├── PortalApplication.java             # @SpringBootApplication entry point
├── controller/
│   ├── AuthController.java            # /api/v1/me  (stub until OAuth2 is back)
│   └── DemoRequestController.java     # /api/v1/public/demo/*
├── sandbox/
│   └── vpn/
│       ├── VpnSandboxController.java  # /api/v1/sandbox/vpn/*
│       └── VpnCryptoService.java      # ML-KEM-1024 / ML-DSA-65 / AES-256-GCM
└── common/
    └── QudoCryptoService.java         # Spring bean wrapping the Qudo JNI provider
```

Future sandbox additions (QRNG, QKD, QHSM, other simulators from the old monorepo) drop in as new packages under `com.pqc.sandbox.*`.
