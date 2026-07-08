# Argus — Kubernetes Deployment

## Quick Start

```bash
# 1. Create the required Kubernetes Secret with real values
kubectl create secret generic argus-secrets --namespace argus \
  --from-literal=DB_PG_HOST=postgres \
  --from-literal=DB_PG_PASSWORD='<real-password>' \
  --from-literal=DB_MYSQL_HOST=mysql \
  --from-literal=DB_MYSQL_PASSWORD='<real-password>' \
  --from-literal=ARGUS_ADMIN_TOKEN='<64-char-random-token>'

# 2. Apply everything
kubectl apply -k k8s/

# Check rollout
kubectl -n argus rollout status deployment/argus
```

## Files

| File | Purpose |
|------|---------|
| `namespace.yaml` | `argus` namespace |
| `serviceaccount.yaml` | ServiceAccount (no token auto-mount) |
| `secret.example.yaml` | Secret template (fill in before deploying) |
| `configmap.yaml` | `argus.json` + base WAF policy |
| `deployment.yaml` | 2-replica Deployment with probes & resource limits |
| `service.yaml` | ClusterIP Services: PG (5432), MySQL (3306), admin (9090), metrics (9091) |
| `hpa.yaml` | HPA: 2–8 replicas based on CPU/memory |
| `pdb.yaml` | PodDisruptionBudget: minAvailable=1 |
| `networkpolicy.yaml` | Ingress + egress restrictions for proxy, admin, metrics |
| `kustomization.yaml` | Kustomize entry point |

## Image Pinning

The kustomization sets `newTag: v0.1.0` as the default image tag. Before
production deployment, pin to an immutable digest:

```yaml
images:
  - name: ghcr.io/ersinkoc/argus
    digest: sha256:abc123...
```

This ensures every deploy runs the exact same image regardless of tag moves.

## Secrets Management

The `secret.example.yaml` file contains placeholder base64 values and is **not** included in
the default kustomization. Before deploying, create the real Secret with one of these methods:

### Option A — kubectl create secret (simplest)

```bash
# Edit secret.example.yaml with real values, then run:
kubectl create secret generic argus-secrets --namespace argus \
  --from-literal=DB_PG_HOST=postgres \
  --from-literal=DB_PG_PASSWORD='<real-password>' \
  --from-literal=DB_MYSQL_HOST=mysql \
  --from-literal=DB_MYSQL_PASSWORD='<real-password>' \
  --from-literal=ARGUS_ADMIN_TOKEN='<64-char-random-token>'
```

Repeat for any other keys (`SIEM_WEBHOOK_URL`, etc.) as needed.

### Option B — External Secrets Operator

Sync from AWS Secrets Manager / GCP Secret Manager / HashiCorp Vault.

### Option C — Sealed Secrets

Encrypt the secret with `kubeseal` before committing the sealed manifest.

## Network Policy (recommended)

`k8s/networkpolicy.yaml` restricts ingress and egress traffic:

- **Ingress**: proxy ports open to any namespace; admin API (9090) restricted to `monitoring`/`ops`; metrics (9091) restricted to `monitoring`
- **Egress**: DNS allowed; DB backends allowed on the cluster pod CIDR; SIEM webhook allowed on port 443

> Adjust the egress `ipBlock` CIDR to match your cluster's pod/service network before deploying.

## Connecting Applications

Applications should connect to Argus instead of the database directly:

```yaml
env:
  - name: DATABASE_URL
    value: "postgresql://user:pass@argus-pg.argus.svc.cluster.local:5432/mydb"
  - name: MYSQL_HOST
    value: "argus-mysql.argus.svc.cluster.local"
```

## Monitoring

The `argus-metrics` service exposes `/metrics` on port 9091 with Prometheus annotations.
