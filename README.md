# Qudo Portal Backend

Spring Boot JSON API that backs the [Qudo Portal Frontend](../qudo-portal-frontend). Self-contained — no microservice fan-out. The new v2 portal is one React SPA + this one Spring Boot app.

## What it serves

| Surface | Path | Auth |
| --- | --- | --- |
| Health | `/actuator/health` | public |
| Current user | `/api/v1/me` | public (returns 401 if not signed in) |
| Demo request | `POST /api/v1/public/demo/request` | public |
| Demo signing pubkey | `GET /api/v1/public/demo/signing-pubkey` | public |
| VPN sandbox | `/api/v1/sandbox/vpn/**` | **signed in** |
| Google OAuth start | `/oauth2/authorization/google` | public |
| Logout | `POST /api/v1/logout` | signed in |

Anonymous users can browse docs and submit demo requests. Sign-in (Google OAuth2) is required to run the sandbox and (when added) download binaries.

## One-time setup

The backend depends on a locally-installed `com.qudo:qudo-jni-crypto:1.0.0` artifact that ships under `libs/`. Install it into your local Maven repo once:

```bash
mvn install:install-file \
  -Dfile=libs/qudo-jni-crypto-1.0.0.jar \
  -DpomFile=libs/qudo-jni-crypto-1.0.0.pom \
  -DgroupId=com.qudo -DartifactId=qudo-jni-crypto -Dversion=1.0.0 -Dpackaging=jar
```

The native library (libqudo_jni_crypto.{so,dylib}) must be on `java.library.path` at runtime — the Docker image places it at `/app/lib`; for local dev, set `-Djava.library.path=...` to wherever you built the native side.

## Google OAuth2 setup

Create an OAuth 2.0 Client ID in [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

- **Application type:** Web application
- **Authorized JavaScript origins:** `http://localhost:5173`, `https://qudo.zenv.ai`
- **Authorized redirect URIs:** `http://localhost:8093/login/oauth2/code/google`, `https://qudo.zenv.ai/login/oauth2/code/google`

Export the client ID and secret before running:

```bash
export GOOGLE_CLIENT_ID=...
export GOOGLE_CLIENT_SECRET=...
export FRONTEND_ORIGIN=http://localhost:5173
```

## Run locally

```bash
mvn spring-boot:run
```

Then start the frontend in the sibling `qudo-portal-frontend` repo. The frontend's Vite dev server proxies `/api/**` and `/oauth2/**` to this backend on port 8093.

## Build for prod

```bash
mvn package
java -jar target/qudo-portal-backend-1.0.0.jar
```

Or via Docker (requires the `qudo-pqc-runtime:latest` base image with the native lib baked in):

```bash
docker build -t qudo-portal-backend:1.0.0 .
docker run -p 8093:8093 \
  -e GOOGLE_CLIENT_ID=... -e GOOGLE_CLIENT_SECRET=... \
  -e FRONTEND_ORIGIN=https://qudo.zenv.ai \
  qudo-portal-backend:1.0.0
```

## Layout

```
src/main/java/com/pqc/
├── backend/
│   ├── BackendApplication.java
│   ├── config/SecurityConfig.java        # OAuth2 + CORS + route-level auth
│   ├── controller/
│   │   ├── AuthController.java           # /api/v1/me
│   │   └── DemoRequestController.java    # /api/v1/public/demo/*
│   └── sandbox/
│       └── vpn/
│           ├── VpnSandboxController.java # /api/v1/sandbox/vpn/* (gated)
│           └── VpnCryptoService.java     # ML-KEM-1024 / ML-DSA-65 / AES-256-GCM
└── common/
    └── QudoCryptoService.java            # Spring bean wrapping the Qudo JNI provider
```

Future sandbox additions (QRNG, QKD, QHSM, other simulators from the old monorepo) drop in as new packages under `com.pqc.backend.sandbox.*`.
