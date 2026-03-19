# Argus — Kubernetes Deployment

## Quick Start

```bash
# 1. Fill in real values in secret.yaml (or use an external secrets manager)
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
| `secret.yaml` | Database credentials and admin token |
| `configmap.yaml` | `argus.json` + base WAF policy |
| `deployment.yaml` | 2-replica Deployment with probes & resource limits |
| `service.yaml` | ClusterIP Services: PG (5432), MySQL (3306), admin (9090), metrics (9091) |
| `hpa.yaml` | HPA: 2–8 replicas based on CPU/memory |
| `pdb.yaml` | PodDisruptionBudget: minAvailable=1 |
| `kustomization.yaml` | Kustomize entry point |

## Secrets Management

The `secret.yaml` file contains placeholder base64 values. In production:

- **External Secrets Operator**: sync from AWS Secrets Manager / GCP Secret Manager / Vault
- **Sealed Secrets**: encrypt with `kubeseal` before committing
- **Vault Agent**: inject secrets as environment variables

## Network Policy (recommended)

Restrict inbound traffic to argus pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: argus-ingress
  namespace: argus
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: argus
  ingress:
    - ports:
        - port: 15432   # PG proxy
        - port: 13306   # MySQL proxy
```

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
