# Qudo Portal — Kubernetes deployment

This directory contains the manifests that deploy `qudo-portal-backend` and
`qudo-portal-frontend` to the **`qudo-portal-dev`** namespace on the RKE2
cluster at `157.173.221.80`, behind the hostname **`dev.qudo.zenv.ai`**.

The previous deployment (an 8-container docker-compose stack at
`/opt/zenv/qudo-pqc-developer-portal/docker/` on the same VPS) is being
retired in favour of this K8s deployment. **The cutover is a hostname
swap on the host nginx** — see [§ Cutover](#cutover) below.

## Topology

```
Internet
   │
   ▼  https://dev.qudo.zenv.ai
host nginx :443  (TLS termination — existing cert)
   │
   ▼  http://localhost:<RKE2-ingress-http-nodeport>
ingress-nginx (cluster)
   │
   ▼  routes by Host header
Service: qudo-portal-frontend :80
   │
   ▼
Pod: qudo-portal-frontend  ────►  (FE nginx proxies /api,/oauth2,/login)
                                       │
                                       ▼  cluster DNS
                              Service: qudo-portal-backend :8093
                                       │
                                       ▼
                              Pod: qudo-portal-backend
                                ├── ConfigMap: qudo-portal-backend-config
                                ├── Secret: qudo-portal-backend-smtp
                                └── PVC: qudo-portal-backend-keys → /var/lib/qudo/keys
```

## File map

| File | What it is |
| --- | --- |
| `01-ghcr-secret.yaml` | Placeholder for the `ghcr-secret` image-pull secret. **Do not commit real credentials.** Create it imperatively (see step 2 below). |
| `02-backend-configmap.yaml` | Non-secret BE env: profile, CORS origin, demo-notify routing, keys dir, SMTP host/port |
| `03-backend-secret.yaml` | SMTP creds template. Replace placeholders or create imperatively. |
| `04-backend-pvc.yaml` | 100Mi PVC at `/var/lib/qudo/keys` so the ML-DSA-65 demo signing key survives pod restarts |
| `05-backend-deployment.yaml` | BE Deployment, 1 replica, K8s-native probes, resource requests/limits |
| `06-backend-service.yaml` | ClusterIP Service — **name `qudo-portal-backend` is required**; the FE nginx hardcodes it |
| `07-frontend-deployment.yaml` | FE Deployment, 1 replica, small footprint, rolling updates |
| `08-frontend-service.yaml` | ClusterIP Service for the FE |
| `09-ingress.yaml` | Ingress, HTTP-only (TLS is upstream), all paths → FE service |

## Prerequisites

- `kubectl` configured against the RKE2 cluster on the VPS
- `docker` locally, plus a GHCR Personal Access Token with `write:packages` scope
- The `qudo-portal-dev` namespace already exists (created 2026-05-22)

## Rollout — first time

```bash
NS=qudo-portal-dev
REGISTRY=ghcr.io/zenvinnovations
TAG=1.0.0
```

### 1. Tag & push images to GHCR

```bash
# Login (one-time per shell)
echo "$GHCR_TOKEN" | docker login ghcr.io -u <your-gh-username> --password-stdin

# Tag the images we built and verified locally
docker tag qudo-portal-backend:1.0.0   $REGISTRY/qudo-portal-backend:$TAG
docker tag qudo-portal-frontend:1.0.0  $REGISTRY/qudo-portal-frontend:$TAG

# Push
docker push $REGISTRY/qudo-portal-backend:$TAG
docker push $REGISTRY/qudo-portal-frontend:$TAG
```

Visit https://github.com/orgs/zenvinnovations/packages and confirm both
packages are listed. By default GHCR creates them as private — that's why
we need `ghcr-secret` on the cluster side.

### 2. Create the image-pull secret in the namespace

```bash
kubectl -n $NS create secret docker-registry ghcr-secret \
    --docker-server=ghcr.io \
    --docker-username='<your-gh-username>' \
    --docker-password="$GHCR_TOKEN" \
    --docker-email='devops@zenv.ai'
```

(The `01-ghcr-secret.yaml` in this directory is a placeholder; the real
secret comes from the imperative command above so the token never lands
in Git.)

### 3. Create the SMTP secret (or skip if you don't have creds yet)

With real creds:

```bash
kubectl -n $NS create secret generic qudo-portal-backend-smtp \
    --from-literal=SMTP_USER_NAME='noreply@zenv.ai' \
    --from-literal=SMTP_PASSWORD='<gmail-app-password>'
```

Without — apply `03-backend-secret.yaml` as-is. Demo form submissions will
still return 200 to the FE; the mail send will fail with a logged WARN
and the request stays in the BE's in-memory list. We disabled the
`MailHealthIndicator` in `application.yml`, so this doesn't take the
`/actuator/health` probe DOWN.

### 4. Apply the rest of the manifests

```bash
kubectl -n $NS apply -f k8s/02-backend-configmap.yaml
kubectl -n $NS apply -f k8s/04-backend-pvc.yaml
kubectl -n $NS apply -f k8s/05-backend-deployment.yaml
kubectl -n $NS apply -f k8s/06-backend-service.yaml
kubectl -n $NS apply -f k8s/07-frontend-deployment.yaml
kubectl -n $NS apply -f k8s/08-frontend-service.yaml
kubectl -n $NS apply -f k8s/09-ingress.yaml
```

Or all at once (after the two `create secret` commands above):

```bash
kubectl -n $NS apply -f k8s/
```

### 5. Wait for pods to come up

```bash
kubectl -n $NS rollout status deployment/qudo-portal-backend
kubectl -n $NS rollout status deployment/qudo-portal-frontend
kubectl -n $NS get pods -o wide
```

Expected:

```
NAME                                    READY   STATUS    RESTARTS   AGE
qudo-portal-backend-...                 1/1     Running   0          30s
qudo-portal-frontend-...                1/1     Running   0          15s
```

### 6. Pre-cutover verification via port-forward (no DNS, no TLS, no host nginx)

```bash
# Smoke-test the BE alone
kubectl -n $NS port-forward svc/qudo-portal-backend 18093:8093 &
curl -s http://localhost:18093/actuator/health/readiness    # {"status":"UP"}
curl -s -X POST http://localhost:18093/api/v1/sandbox/primitives/health
kill %1

# Smoke-test the FE serving SPA + proxying /api to BE Service
kubectl -n $NS port-forward svc/qudo-portal-frontend 18080:80 &
curl -sI http://localhost:18080/                            # 200, text/html (index.html)
curl -s  http://localhost:18080/api/v1/sandbox/primitives/health
kill %1
```

If both return what we saw locally (BE health UP, FE serves SPA + proxy
works), the in-cluster wiring is correct.

## Cutover

The hostname `dev.qudo.zenv.ai` is currently served by the **host nginx
on the VPS**, which reverse-proxies to the docker-compose
`nginx-gateway` on `:8880`. To put K8s behind that hostname instead,
edit the host nginx's server-block for `dev.qudo.zenv.ai` and change
the upstream port from `:8880` → the RKE2 ingress-nginx HTTP NodePort.

### Find the K8s ingress HTTP NodePort

```bash
ssh root@157.173.221.80 \
  kubectl -n ingress-nginx get svc ingress-nginx-controller \
    -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}{"\n"}'
```

(On this cluster's RKE2 install the ingress already listens on a fixed
HTTP port; the host nginx earlier output showed `:3081` and `:3443` as
candidates. Confirm via the command above before the flip.)

### Flip the host nginx upstream

On the VPS, find the server block:

```bash
ssh root@157.173.221.80 \
  grep -rl 'dev.qudo.zenv.ai' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/
```

Edit the matching file; inside the `location /` block change:

```nginx
proxy_pass http://127.0.0.1:8880;
```

to:

```nginx
proxy_pass http://127.0.0.1:<RKE2-ingress-http-nodeport>;
```

Reload:

```bash
ssh root@157.173.221.80 'nginx -t && systemctl reload nginx'
```

The old docker-compose containers keep running on `qudo-net` and on
`:8880`; they just no longer receive traffic from the hostname.

### Verify end-to-end

```bash
# SPA loads
curl -sI https://dev.qudo.zenv.ai/ | head -3        # HTTP/2 200

# Scanner round-trips via FE → BE → openssl
curl -s -X POST https://dev.qudo.zenv.ai/api/v1/scan \
    -H 'Content-Type: application/json' \
    -H 'Origin: https://dev.qudo.zenv.ai' \
    -d '{"host":"google.com:443"}' | jq '.score,.tlsInfo.keyExchange'
# 70
# "X25519MLKEM768"

# Demo request (best-effort mail send)
curl -s -X POST https://dev.qudo.zenv.ai/api/v1/public/demo/request \
    -H 'Content-Type: application/json' \
    -H 'Origin: https://dev.qudo.zenv.ai' \
    -d '{"name":"K8s test","email":"k8s@example.com","organization":"Acme","message":"deploy test"}' | jq
```

Open https://dev.qudo.zenv.ai in a browser — full SPA experience with
real BE.

## Rollback

If anything looks wrong, the rollback is **the inverse of the cutover**:
re-edit the host nginx's `proxy_pass` for `dev.qudo.zenv.ai` back to
`:8880`, reload nginx, and the old docker-compose stack reappears
instantly. K8s resources stay running in the background — nothing to
tear down.

If the K8s deployment itself is broken (pods crashing, image pull fails,
etc) you can scale to zero without affecting the cutover state:

```bash
kubectl -n qudo-portal-dev scale deploy qudo-portal-backend  --replicas=0
kubectl -n qudo-portal-dev scale deploy qudo-portal-frontend --replicas=0
```

## Day-2 operations

```bash
# Tail BE logs (JSON format — pipe through jq for readability)
kubectl -n qudo-portal-dev logs -f deploy/qudo-portal-backend | jq -rR '. as $line | try (fromjson | "\(."@timestamp")  \(.level)  \(.logger_name)  \(.message)") catch $line'

# Tail FE logs
kubectl -n qudo-portal-dev logs -f deploy/qudo-portal-frontend

# Restart BE (after a config change in the ConfigMap or Secret)
kubectl -n qudo-portal-dev rollout restart deploy/qudo-portal-backend

# Confirm signing keys survived a restart — should say "Loaded existing"
# not "Generated new ML-DSA-65 keypair".
kubectl -n qudo-portal-dev logs deploy/qudo-portal-backend | grep -i "signing key"

# Hop into the pod for diagnostics
kubectl -n qudo-portal-dev exec -it deploy/qudo-portal-backend -- bash
```

## Updating to a new image version

1. Build, tag, push:
   ```bash
   docker build -t qudo-portal-backend:1.0.1 .
   docker tag  qudo-portal-backend:1.0.1 ghcr.io/zenvinnovations/qudo-portal-backend:1.0.1
   docker push ghcr.io/zenvinnovations/qudo-portal-backend:1.0.1
   ```
2. Bump the `image:` tag in `05-backend-deployment.yaml`.
3. `kubectl -n qudo-portal-dev apply -f k8s/05-backend-deployment.yaml`.
4. `kubectl -n qudo-portal-dev rollout status deploy/qudo-portal-backend`.

## Known limitations (intentional, deferred for v1)

- **1 replica per Deployment.** RateLimitFilter buckets + the in-memory
  demo-request list live in the JVM heap and don't sync across pods.
  Replace with Bucket4j+Redis to scale out.
- **No NetworkPolicy.** Any pod in any namespace can reach the BE
  Service. Add a NetworkPolicy that only allows the FE pod once we
  introduce noisier neighbours.
- **No HPA / VPA.** Single-replica makes both pointless today.
- **TLS terminated upstream.** cert-manager isn't issuing the cert for
  this app — the host nginx's existing cert is reused. To switch to
  cert-manager later, add a `tls:` section + the
  `cert-manager.io/cluster-issuer: letsencrypt-prod` annotation, then
  remove the cert from the host nginx and have host nginx do
  pure-passthrough on port 443 to the K8s ingress's HTTPS port.
- **No ArgoCD app yet.** Applying via `kubectl apply` for v1; once
  manifests stabilise, wrap in an ArgoCD Application pointing at this
  directory so GitOps takes over.
