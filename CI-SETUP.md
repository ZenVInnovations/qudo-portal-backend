# CI/CD setup — one-time configuration

Everything below needs to happen **once per repo** before the GitHub
Actions workflows can deploy to the cluster. After this, every push to
`main` auto-deploys to `dev.qudo.zenv.ai`, and production deploys are
triggered manually from the Actions tab.

## Workflows in this repo

| File | When it runs | What it does |
|---|---|---|
| `.github/workflows/main.yml` | Push to `main` (auto), or manual `workflow_dispatch` | `mvn package`, build Docker image, push to GHCR as `:sha-<7>` + `:main`, `kubectl set image` against `qudo-portal-dev`, wait for rollout, smoke-test `dev.qudo.zenv.ai`. **Dev only, automatic.** |
| `.github/workflows/deploy.yml` | Manual `workflow_dispatch` only — `environment` is a dropdown choice | Targets **dev or prod** based on the input. Retag-or-build (see below), `kubectl set image` against the chosen namespace, smoke-test the corresponding public URL. |

The frontend repo has the same shape and shares the same `KUBECONFIG_DEV`
+ `KUBECONFIG_PROD` secrets.

### No PR-time CI

Deliberate choice: we don't run a `pr.yml`. Merges trigger `main.yml`
which auto-deploys to dev. The trade-off is that broken Dockerfiles /
dependency bumps surface post-merge instead of pre-merge. Mitigation:
dev going red is loud and recoverable in minutes.

## deploy.yml — unified manual deploy (dev or prod)

Triggered from **Actions tab → "Deploy" → Run workflow**. Four inputs:

| Input | What it is |
|---|---|
| `environment` | Dropdown choice: `dev` or `prod`. Selects the namespace, kubeconfig secret, public URL, alias tag, and GitHub Environment (approval gate). |
| `commit_sha` | 7-char short SHA of the commit you want live |
| `version` | Human-readable label (`v1.0.1`, `rollback-2026-05-25`, etc.) — applied as a permanent image tag + a Deployment annotation |
| `reason` | Why this deploy is happening — captured in the GitHub Environment history |

### What `environment` controls

| When you pick… | Namespace | KUBECONFIG secret | URL | Alias tag | Approval gate |
|---|---|---|---|---|---|
| **`dev`** | `qudo-portal-dev` | `KUBECONFIG_DEV` | `https://dev.qudo.zenv.ai` | `:dev` | None — fires immediately |
| **`prod`** | `qudo-portal-prod` | `KUBECONFIG_PROD` | `https://qudo.zenv.ai` | `:prod` | Required reviewers on the `production` GH Environment |

### When you'd use deploy.yml against dev (vs let main.yml handle it)

- **Roll dev back** to a previous commit without making a new merge to main
- **Redeploy a specific past commit** to dev to reproduce a bug
- **Test a commit from a branch** before merging it (the workflow checks out by SHA, not by branch — anything pushed to GHCR or buildable from a commit on origin works)
- **Promote bits** from dev to prod with the exact same SHA (audit-clean)

For "I just merged to main and want it on dev" — main.yml has already
done that auto. No need to trigger deploy.yml.

### How it decides between retag and rebuild

```
GHCR has ghcr.io/.../<repo>:sha-<commit_sha>?
├── YES  → PATH A — server-side retag (no layer transfer)
│           adds :<version> + :<env> (:dev or :prod)
│           kubectl set image → rollout → smoke test
└── NO   → PATH B — build from the exact commit
           docker build (from the checked-out source) →
           push all three tags atomically :sha-<commit_sha> + :<version> + :<env> →
           kubectl set image → rollout → smoke test
```

Path A is the normal case (commit was already built by main.yml). Path B
covers commits main.yml never built — failed pipeline, long-lived
release branch, etc. — so you can still deploy them without manually
re-running main.yml first.

After a successful deploy, GHCR has these tags pointing at one image:

| Tag | Mutable? | Used by |
|---|---|---|
| `:sha-1a2b3c4` (the canonical SHA) | **No** | Deployment `image:` field (immutable reference) |
| `:v1.0.1` (the version label) | **No, never overwritten** | Permanent record of "what version X was"; release notes |
| `:dev` / `:prod` | **Yes, moves to whatever's live now** | GHCR UI sanity check; never referenced from manifests |
| `:main` (pushed only by `main.yml`, not `deploy.yml`) | Yes, moves per main build | GHCR UI; never referenced from manifests |

## Required GitHub secrets

| Secret | Required for | What goes in it |
|---|---|---|
| `KUBECONFIG_DEV` | `main.yml` | base64-encoded kubeconfig for the `github-deployer` ServiceAccount in `qudo-portal-dev` |
| `KUBECONFIG_PROD` | `prod-deploy.yml` | base64-encoded kubeconfig for the (future) prod cluster's deploy ServiceAccount |
| `VITE_SENTRY_DSN` | optional (FE) | Sentry DSN; if absent the FE Sentry init is a no-op |

`GITHUB_TOKEN` is auto-provided and has `packages:write` for pushing to
GHCR via the workflow `permissions:` block.

### Generating `KUBECONFIG_DEV`

The `github-deployer` ServiceAccount and its `deployer` Role are already
on the cluster (created 2026-05-22). Run on the VPS:

```bash
ssh root@157.173.221.80 bash -s << 'SCRIPT'
NS=qudo-portal-dev
SA=github-deployer
SECRET=github-deployer-token
APISERVER='https://157.173.221.80:6443'

TOKEN=$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.token}' | base64 -d)
CA_B64=$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.ca\.crt}')

cat << YAML | base64 -w0
apiVersion: v1
kind: Config
clusters:
- name: qudo-dev-vps
  cluster:
    server: $APISERVER
    certificate-authority-data: $CA_B64
contexts:
- name: $SA@qudo-dev-vps
  context:
    cluster: qudo-dev-vps
    namespace: $NS
    user: $SA
current-context: $SA@qudo-dev-vps
users:
- name: $SA
  user:
    token: $TOKEN
YAML
echo
SCRIPT
```

Paste the base64 output (one long line, no newlines) into the
`KUBECONFIG_DEV` secret in repo Settings → Secrets and variables →
Actions. Same value works for both repos.

`KUBECONFIG_PROD` is generated the same way against the prod
cluster + prod namespace once those exist.

### Verify the dev secret works

```bash
echo '<paste the base64 here>' | base64 -d | \
  kubectl --kubeconfig=/dev/stdin -n qudo-portal-dev get deploy
# Should list qudo-portal-backend and qudo-portal-frontend
```

## GitHub Environments

Both workflows use GitHub Environments — configure under repo Settings
→ Environments.

### `dev` environment

- Used by both `main.yml` (auto-deploy) and `deploy.yml` (when
  `environment: dev` is selected).
- **No required reviewers** — auto-deploys are the whole point.
- Set the environment URL to `https://dev.qudo.zenv.ai`.
- Optionally restrict deployment branches to `main` only.

### `production` environment

- Used by `deploy.yml` when `environment: prod` is selected.
- **Required reviewers**: add the people allowed to approve prod
  deploys. The workflow pauses until an approver clicks
  "Approve and deploy".
- Set the environment URL to `https://qudo.zenv.ai` (update if prod
  hostname changes).
- Restrict deployment branches to `main` only — no feature branches
  can deploy to prod.

## What the SAs can and cannot do

The `deployer` Role (bound to `github-deployer` in `qudo-portal-dev`):

| Verb on | Resource |
|---|---|
| `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | `deployments`, `replicasets`, `statefulsets` (apps) |
| `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | `services`, `configmaps`, `pods`, `pods/log`, `secrets` (core) |
| `get`, `list`, `watch`, `create`, `delete` | `jobs` (batch) |
| `get`, `list`, `watch`, `create`, `update`, `patch` | `ingresses` (networking.k8s.io) |
| `get`, `list`, `watch`, `create`, `update`, `patch` | `horizontalpodautoscalers` (autoscaling) |

**Namespace-scoped.** Leaked CI token can deploy code into one dev
namespace on one VPS — bad, but contained. Cannot list nodes, touch
kube-system, modify cluster-scoped resources, or escalate to admin.

## Image tagging convention

| Tag | When | Who consumes |
|---|---|---|
| `:sha-1a2b3c4` | Every `main.yml` build, every `prod-deploy.yml` build-fallback | Deployment manifests in K8s |
| `:main` | Every `main.yml` build | Human eyeballs in the GHCR UI; never referenced from manifests |
| `:<version>` (e.g. `:v1.0.1`) | Every `prod-deploy.yml` run, on the commit deployed | Permanent, immutable reference to "what version X was" |
| `:prod` | Every `prod-deploy.yml` run | Floating alias for "what's currently in prod" — useful for `docker pull ghcr.io/.../qudo-portal-backend:prod` to mirror prod locally |

**Never** put `:latest` on anything we ship. Tag rotation under floating
tags is the #1 source of "I deployed exactly what was there yesterday,
why is the behavior different?" mysteries.

## Rollback

### From the GitHub Actions UI (preferred — auditable)

Re-run `prod-deploy.yml` with the **previous** good commit's SHA. The
retag step makes that SHA the new `:prod` and the cluster rolls to it.

### From kubectl (fast — for breaking incidents)

```bash
# Roll back to the previous Deployment revision (no SHA needed)
kubectl -n qudo-portal-prod rollout undo deploy/qudo-portal-backend
kubectl -n qudo-portal-prod rollout status deploy/qudo-portal-backend
```

`rollout undo` uses the Deployment's revision history (default 10
revisions kept) — instant rollback to whatever was running before the
last `set image`.

## Manifest drift caveat

The `image:` line in `k8s/05-backend-deployment.yaml` reads
`ghcr.io/zenvinnovations/qudo-portal-backend:1.0.0`. CI overrides this
via `kubectl set image`, so the live cluster runs `:sha-<7>` (or
`:v1.0.1`), but the YAML in git still says `:1.0.0`.

Implications:

- `kubectl apply -f k8s/` (without CI in the loop) would **reset** the
  cluster to `:1.0.0`. Don't do this between deploys; let CI handle it.
- When we move to ArgoCD (Phase 2), CI will commit the SHA tag back into
  the YAML and ArgoCD will reconcile — drift goes away.

## Day-2 ops

```bash
# Tail BE logs (pretty-printed JSON)
kubectl -n qudo-portal-dev logs -f deploy/qudo-portal-backend | jq -rR '. as $l | try (fromjson | "\(.[\"@timestamp\"])  \(.level)  \(.logger_name)  \(.message)") catch $l'

# Tail FE logs (nginx)
kubectl -n qudo-portal-dev logs -f deploy/qudo-portal-frontend

# Trigger a redeploy without a new image (e.g. ConfigMap changed)
kubectl -n qudo-portal-dev rollout restart deploy/qudo-portal-backend

# See what's currently running (image tag tells you the SHA)
kubectl -n qudo-portal-dev get deploy qudo-portal-backend -o jsonpath='{.spec.template.spec.containers[0].image}'
# → ghcr.io/zenvinnovations/qudo-portal-backend:sha-1a2b3c4

# Read the audit annotations on a prod deploy
kubectl -n qudo-portal-prod get deploy qudo-portal-backend -o jsonpath='{.metadata.annotations}' | jq .
# → { "qudo.zenv.ai/version": "v1.0.1", "qudo.zenv.ai/commit-sha": "1a2b3c4",
#     "qudo.zenv.ai/deployed-by": "srimanreddy99", "qudo.zenv.ai/reason": "..." }
```
