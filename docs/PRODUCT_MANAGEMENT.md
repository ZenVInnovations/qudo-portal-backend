# Product Management

The Qudo portal shows a **catalog of products**. The **backend is the single source
of truth** for which products are publicly visible; the frontend renders whatever the
backend returns and holds no hard-coded product-visibility logic. Administrators toggle
products on/off through an authenticated Admin Portal.

This document is for developers and operators maintaining that system across the two
repos: `qudo-portal-backend` (this repo) and `qudo-portal-frontend`.

---

## Architecture

### Backend (source of truth)

- **Storage:** PostgreSQL via Spring Data JPA + Flyway. Postgres is required — start it
  locally with `docker compose up -d`.
- **Product model** — table `products` (`db/migration/V1__create_products.sql`), entity
  `com.pqc.product.Product`:

  | column | meaning |
  |---|---|
  | `product_key` | **stable external identifier** (never the display name) |
  | `name`, `tagline`, `description` | display content |
  | `enabled` | on/off |
  | `display_order` | sort order on the public site |
  | `visibility` | `PUBLIC` or `HIDDEN` |
  | `product_type` | `QUDOSSL_EDITION` / `PROVIDER` / `LIBRARY` |
  | `edition` | `COMMUNITY` / `COMMERCIAL` (null otherwise) |
  | `documentation_url`, `repository_url` | links |
  | `created_at`, `updated_at` | timestamps |

  **A product appears publicly only when `enabled = true` AND `visibility = 'PUBLIC'`.**

- **Audit** — table `product_audit` (`V2`), entity `ProductAuditEntry`. One row is written
  per changed field on every admin mutation: `product_key`, `admin_username`,
  `field_changed`, `old_value`, `new_value`, `changed_at`.

- **Seed** — `V3__seed_products.sql` inserts the initial catalog idempotently
  (`ON CONFLICT (product_key) DO NOTHING`), so re-running or redeploying never clobbers an
  operator's later changes.

### APIs

Public (permit-all chain, `PublicProductController`):

```
GET /api/v1/public/products      → enabled + PUBLIC products only, ordered; minimal fields
```

The public DTO intentionally omits `id`, `enabled`, `visibility`, timestamps — a disabled
or hidden product is never returned, so those never need to be exposed.

Admin (authenticated `ROLE_ADMIN` chain, `AdminProductController` / `AdminAuthController`):

```
POST /api/v1/admin/login         { username, password }  → sets session cookie
POST /api/v1/admin/logout
GET  /api/v1/admin/me            → { username } (401 if not signed in)
GET  /api/v1/admin/products      → all products (full fields)
PUT  /api/v1/admin/products/{id} → partial update (enabled, displayOrder, visibility, metadata)
GET  /api/v1/admin/products/{id}/audit → recent audit entries
```

### Authentication & authorization

- Two Spring Security filter chains (`com.pqc.config.SecurityConfig`):
  - **admin chain** — `securityMatcher("/api/v1/admin/**")`, requires `ROLE_ADMIN`, session
    cookie, CSRF enabled with a JS-readable `XSRF-TOKEN` cookie.
  - **public chain** — everything else, unchanged: stateless + permit-all (the sandbox/demo
    surface stays free, defended by the per-IP rate limiter).
- **Single admin credential from env**: `ADMIN_USERNAME` + `ADMIN_PASSWORD_HASH` (a **BCrypt
  hash**, never plaintext). `dev`/`prod` **fail to start** if unset; the `local` profile ships
  a dev-only default (`admin` / `qudo-admin-dev`) that is never used in a deployment.
  - Generate a hash: `htpasswd -nbBC 10 "" 'your-password' | cut -d: -f2`

### Frontend integration

- API layer: `src/api/products.ts` (public) and `src/api/admin.ts` (admin). Both go through
  `src/api/client.ts`, which already sends the session cookie (`credentials: 'include'`) and
  the `XSRF-TOKEN → X-XSRF-TOKEN` header on mutations.
- Public rendering: `src/components/ProductsSection.tsx` (used on the home page and
  `/products`) fetches the catalog and renders it. QudoSSL product pages live at
  `/products/:key`; migration guides at `/migration` and `/migration/:key`.
- Admin portal: `/admin` (product-management screen with ON/OFF toggles) and `/admin/login`,
  guarded by `src/admin/ProtectedRoute.tsx` + `src/admin/AuthContext.tsx`.

### Fail-closed & caching

- **Fail-closed (security):** if the public products API is unavailable, the site shows a
  controlled "temporarily unavailable" message and renders **no products** — it never falls
  back to a hard-coded list and never risks showing a disabled product.
- **Caching:** none server-side. The frontend fetches on load, so an admin change propagates
  on the next public page load (effectively immediate). No cache to invalidate.

---

## Current products

| key | product | status |
|---|---|---|
| `qudossl-community` | QudoSSL Community Edition | **Enabled** |
| `qudossl-commercial` | QudoSSL Commercial Edition | **Enabled** |
| `qudoprovider` | Qudo Provider | Disabled (parked) |
| `qudopqc` | Qudo PQC | Disabled (parked) |

`qudoprovider` and `qudopqc` are **parked, not deleted** — they remain in the catalog as
disabled rows and can be re-enabled at any time from the Admin Portal.

---

## How to enable / disable a product

**Via the Admin Portal (operators):**

1. Go to `/admin`, sign in with the admin credential.
2. Flip the product's **ON/OFF** toggle. Disabling a public product asks for confirmation
   (it disappears from the public site immediately). The change is recorded in the audit trail.

**Via the API (developers/automation):**

```bash
# 1. Get an XSRF token + session by signing in (cookies stored in cookies.txt)
curl -sc cookies.txt http://localhost:8093/api/v1/admin/me            # seeds XSRF-TOKEN
XSRF=$(awk '/XSRF-TOKEN/{print $7}' cookies.txt)
curl -sb cookies.txt -c cookies.txt -H "X-XSRF-TOKEN: $XSRF" \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"…"}' \
     http://localhost:8093/api/v1/admin/login

# 2. Toggle a product (id from GET /api/v1/admin/products)
XSRF=$(awk '/XSRF-TOKEN/{print $7}' cookies.txt)
curl -sb cookies.txt -H "X-XSRF-TOKEN: $XSRF" -H 'Content-Type: application/json' \
     -X PUT -d '{"enabled":false}' \
     http://localhost:8093/api/v1/admin/products/3
```

---

## Adding a future product

No portal redesign is needed:

1. **Backend:** add a Flyway migration (e.g. `V4__seed_new_product.sql`) inserting the row
   with a new stable `product_key`, `product_type`, order, and `enabled`/`visibility`.
2. **Frontend (only if it needs a dedicated detail page):** add an entry to
   `src/data/product-content.tsx` and set the seed row's `documentation_url` to
   `/products/<key>`. Products without a dedicated page can still list and link out via
   `repository_url`.
3. Deploy. The public API and the Admin Portal pick up the new product automatically.

---

## Local development

```bash
docker compose up -d                       # Postgres (product catalog + audit)
export ADMIN_USERNAME=admin                # or rely on the local-profile dev default
# export ADMIN_PASSWORD_HASH=...           # optional; local ships a dev default
mvn -Dspring-boot.run.profiles=local spring-boot:run   # needs the native crypto lib on java.library.path
```

Tests: `mvn test` runs unit + web-slice tests (no DB/native lib needed) plus a
Testcontainers repository test that is **skipped automatically when Docker is unavailable**.
