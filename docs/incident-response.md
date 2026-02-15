# Incident Response: Rejection Rate Spike

**Alert:** `HighRejectionRate` or `RejectionRateSpike`
**Severity:** Warning → potentially Critical
**Typical trigger:** 3 AM PagerDuty/alert notification indicating rejection rate has spiked significantly above the ~15% baseline.

---

## System Overview (for the unfamiliar engineer)

This is an **LLM Agent API** that accepts user messages via `POST /ask` and either returns a response or rejects the request. Rejections are based on deterministic regex pattern matching across three categories:

| Rejection Reason   | What It Catches                              | Pattern IDs |
| ------------------ | -------------------------------------------- | ----------- |
| `prompt_injection` | Attempts to override system instructions     | pi_1–pi_8   |
| `secrets_request`  | Requests for passwords, API keys, tokens     | sr_1–sr_8   |
| `dangerous_action` | Commands like `rm -rf`, `drop table`, `sudo` | da_1–da_10  |

**Architecture:**

Production runs on **Kubernetes** (see `deployment/manifest.yml`). The agent-api deployment has **2 replicas**, 500m CPU / 512Mi memory limits, and a `/healthz` health check. Docker Compose is used for local development only.

| Component         | Port | Purpose                                               | Production Runtime          |
| ----------------- | ---- | ----------------------------------------------------- | --------------------------- |
| agent-api         | 8080 | Flask API (endpoints: `/ask`, `/healthz`, `/metrics`) | K8s Deployment (2 replicas) |
| traffic-generator | —    | Sends synthetic traffic (~15% rejection mix)          | K8s Deployment              |
| prometheus        | 9090 | Metrics collection (scrapes every 5s)                 | K8s / managed service       |
| grafana           | 3000 | Dashboards (login: admin/admin)                       | K8s / managed service       |

**Normal baseline:** ~14–15% rejection rate under standard traffic-generator load (`REJECTION_MIX_RATIO=0.15`).

**Alert thresholds (from [prometheus/alert-rules.yml](../prometheus/alert-rules.yml)):**

- `HighRejectionRate`: >25% of `/ask` requests rejected over a 5-minute window, sustained for 5 minutes.
- `RejectionRateSpike`: Current 5-min rejection rate is >2× the rate from 1 hour ago (and rate > 0.1 req/s), sustained for 5 minutes.

---

## 1. Initial Triage and Assessment (first 5 minutes)

**Goal:** Determine severity and blast radius. Is this impacting real users or just noisy traffic?

### 1.1 Confirm the alert is real

Open Prometheus and verify the alert is still firing:

```
http://localhost:9090/alerts
```

Run these PromQL queries in Prometheus (`http://localhost:9090/graph`):

```promql
# Current rejection rate (should be ~0.15 normally)
sum(rate(agent_rejections_total[5m])) / sum(rate(agent_requests_total{route="/ask"}[5m]))
```

```promql
# Is the API up?
up{job="agent-api"}
```

### 1.2 Check API health

```bash
# Via port-forward or ingress/service URL in production
kubectl port-forward svc/agent-api 8080:8080 &
curl -s http://localhost:8080/healthz | jq .
# Expected: {"status": "healthy", "prompt_version": "v1.0.0"}
```

### 1.3 Verify pods and deployment status

```bash
# Check pod status — are all replicas running?
kubectl get pods -l app=agent-api
kubectl get deployment agent-api

# Describe deployment for events (crash loops, image pull errors, OOMKills)
kubectl describe deployment agent-api

# Check recent pod logs
kubectl logs -l app=agent-api --tail=50

# If a specific pod is crashing, inspect it
kubectl describe pod <pod-name>
kubectl logs <pod-name> --previous   # logs from the last crashed container
```

> **Local dev (Docker Compose):** `docker compose ps` and `docker compose logs --tail=50 agent-api`

### 1.4 Assess the scope

```promql
# Total request rate — is traffic volume normal or has it spiked too?
sum(rate(agent_requests_total{route="/ask"}[5m]))

# Rejection rate by reason — which category is causing the spike?
sum by (reason)(rate(agent_rejections_total[5m]))

# Rejection rate by specific pattern
sum by (pattern_id, reason)(rate(agent_rejection_pattern_total[5m]))
```

### 1.5 Record the timeline

Note the following in the incident channel:

- **Time alert fired:**
- **Current rejection rate:** (from query above)
- **Baseline rejection rate:** ~15%
- **API health:** (healthy / degraded / down)
- **Prompt version:** (from `/healthz` response)

---

## 2. Investigation Steps

### 2.1 Determine the rejection category driving the spike

```promql
# Breakdown by reason over last 15 minutes
sum by (reason)(increase(agent_rejections_total[15m]))
```

This tells you **what kind** of content is being rejected:

| If dominant reason is... | Likely cause                                       |
| ------------------------ | -------------------------------------------------- |
| `prompt_injection`       | Targeted attack / adversarial traffic              |
| `secrets_request`        | Automated probing / credential stuffing            |
| `dangerous_action`       | Automated attack or compromised integration        |
| `invalid_request`        | Client bug sending malformed payloads              |
| Multiple reasons equally | Broad attack or traffic-generator misconfiguration |

### 2.2 Check for traffic anomalies

```promql
# Has total traffic volume spiked? (compare to 1 hour ago)
sum(rate(agent_requests_total{route="/ask"}[5m]))
/
sum(rate(agent_requests_total{route="/ask"}[5m] offset 1h))
```

- **Ratio ≈ 1.0:** Traffic volume normal → rejection pattern has changed, not traffic volume.
- **Ratio >> 1.0:** Traffic volume itself has spiked → possible attack or runaway client.

### 2.3 Check for deployment-related causes

```promql
# Compare rejection rate across prompt versions
sum by (prompt_version)(rate(agent_rejections_total[5m]))
/ on(prompt_version)
sum by (prompt_version)(rate(agent_requests_total{route="/ask"}[5m]))
```

```bash
# Check current prompt version
curl -s http://localhost:8080/healthz | jq .prompt_version

# Check what image/tag is currently deployed
kubectl get deployment agent-api -o jsonpath='{.spec.template.spec.containers[0].image}'

# Check PROMPT_VERSION env var on running pods
kubectl exec deploy/agent-api -- env | grep PROMPT_VERSION

# Check deployment manifest for recent changes
cat deployment/manifest.yml | grep image_tag

# View rollout history
kubectl rollout history deployment/agent-api

# Check git log for recent changes
git log --oneline -10
```

If a new `PROMPT_VERSION` or image tag was deployed recently, the deployment likely caused the spike.

### 2.4 Check the traffic generator

```bash
# Is the traffic generator pod running?
kubectl get pods -l app=traffic-generator
kubectl logs -l app=traffic-generator --tail=30

# Check the configured rejection mix ratio
kubectl exec deploy/traffic-generator -- env | grep REJECTION_MIX_RATIO
# Expected: 0.15
```

> **Local dev (Docker Compose):** `docker compose logs --tail=30 traffic-generator`

If `REJECTION_MIX_RATIO` was changed or the generator is misconfigured, that's the root cause.

### 2.5 Check for application errors

```promql
# Are there unhandled exceptions?
sum(rate(agent_exceptions_total[5m]))

# HTTP 5xx rate
sum(rate(agent_http_responses_total{status_code="500"}[5m]))
```

```bash
# Check application logs for exceptions
kubectl logs -l app=agent-api --tail=100 | grep -i "error\|exception\|traceback"

# Check for OOMKill or resource pressure
kubectl top pods -l app=agent-api
kubectl describe pod -l app=agent-api | grep -A5 "Last State"
```

> **Local dev (Docker Compose):** `docker compose logs --tail=100 agent-api | grep -i "error\|exception\|traceback"`

### 2.6 Check latency for degradation

```promql
# P99 latency — is the API slowing down?
histogram_quantile(0.99, sum by (le)(rate(agent_request_latency_seconds_bucket[5m])))
```

### 2.7 Inspect raw metrics directly

```bash
# Port-forward to a specific pod and pull raw metrics
kubectl port-forward svc/agent-api 8080:8080 &
curl -s http://localhost:8080/metrics | grep agent_rejections_total

# Look at rejection counts by reason and pattern
curl -s http://localhost:8080/metrics | grep agent_rejection_pattern_total

# Or exec into a pod and curl localhost
kubectl exec deploy/agent-api -- curl -s http://localhost:8080/metrics | grep agent_rejections_total
```

### 2.8 Open Grafana dashboard

Navigate to `http://localhost:3000` (admin/admin) and open the **Agent Monitoring** dashboard. Inspect:

- **Request Rate** panel — is traffic volume normal?
- **Rejection Rate** panel — when did the spike begin? Does it correlate with a deployment?
- **Latency** panels — is the system under resource pressure?

---

## 3. Decision Framework: Mitigate vs. Escalate

```
                          Is the API healthy?
                         /                  \
                       YES                   NO
                        |                     |
              Is this attack traffic?    ──► ESCALATE (P1)
               /              \              Restart: kubectl rollout restart deploy/agent-api
             YES               NO            If still down: check pods, events, and resources
              |                 |
   Rate > 50%?          Was there a recent deploy?
    /       \              /           \
  YES       NO           YES           NO
   |         |            |             |
ESCALATE  MONITOR     ROLLBACK      INVESTIGATE
 (P2)     for 15min   prompt ver.   further
                       or image
```

### When to MITIGATE (you can handle this yourself)

- **Traffic generator misconfiguration:** Fix `REJECTION_MIX_RATIO` in the deployment spec, then apply:

  ```bash
  # Edit the traffic-generator deployment to fix REJECTION_MIX_RATIO
  kubectl set env deploy/traffic-generator REJECTION_MIX_RATIO=0.15
  # Or restart it
  kubectl rollout restart deploy/traffic-generator
  ```

- **Bad deployment / prompt version:** Roll back to the previous revision:

  ```bash
  # Roll back agent-api to the previous known-good version
  kubectl rollout undo deployment/agent-api

  # Or roll back to a specific revision
  kubectl rollout history deployment/agent-api
  kubectl rollout undo deployment/agent-api --to-revision=<N>

  # Verify rollback succeeded
  kubectl rollout status deployment/agent-api
  ```

- **Transient spike that is self-resolving:** Monitor for 15 minutes. If rate returns below 25%, document and close.

### When to ESCALATE

| Condition                                                          | Severity      | Action                                              |
| ------------------------------------------------------------------ | ------------- | --------------------------------------------------- |
| API is down (`up{job="agent-api"} == 0`)                           | P1 – Critical | Page the team lead immediately                      |
| Rejection rate > 50% and rising                                    | P2 – High     | Escalate to security team — likely an active attack |
| Rejection concentrated in `prompt_injection` from external sources | P2 – High     | Engage security; consider rate limiting upstream    |
| Rollback did not resolve the issue                                 | P2 – High     | Escalate to the development team                    |
| Exception rate is spiking alongside rejections                     | P2 – High     | Application bug — escalate to dev team              |
| You cannot determine root cause within 30 minutes                  | P3 – Medium   | Escalate with all collected evidence                |

### Emergency stop (last resort)

If the system is causing broader harm (e.g., downstream impact), stop all traffic:

```bash
# Scale down the traffic generator to halt synthetic load
kubectl scale deploy/traffic-generator --replicas=0

# If necessary, scale down the agent-api itself
kubectl scale deploy/agent-api --replicas=0

# To restore later:
kubectl scale deploy/agent-api --replicas=2
kubectl scale deploy/traffic-generator --replicas=1
```

> **Local dev (Docker Compose):** `docker compose stop traffic-generator` or `docker compose down`

---

## 4. Post-Incident Actions

### 4.1 Immediate (within 1 hour of resolution)

- [ ] Confirm rejection rate has returned to baseline (~15%):
  ```promql
  sum(rate(agent_rejections_total[5m])) / sum(rate(agent_requests_total{route="/ask"}[5m]))
  ```
- [ ] Verify no other alerts are firing: `http://localhost:9090/alerts`
- [ ] Post a summary in the incident channel with: timeline, root cause, resolution, and current status.

### 4.2 Short-term (within 24 hours)

- [ ] Run the evaluation suite to verify system correctness:

  ```bash
  make eval
  ```

  Check results in `eval-results/eval-summary.json`. Expected thresholds:
  - Golden accuracy ≥ 90% (legitimate messages accepted)
  - Golden rejection rate ≤ 5% (false positives)
  - Adversarial rejection rate ≥ 60% (malicious messages caught)

- [ ] Review the Grafana dashboard over the full incident window — look for patterns you missed in real time.

- [ ] If a deployment caused the issue, verify the fix is merged and the deployment manifest (`deployment/manifest.yml`) reflects the corrected `image_tag`.

### 4.3 Post-mortem (within 3 business days)

Write a post-mortem covering:

1. **Timeline:** When the alert fired, when it was acknowledged, when it was resolved.
2. **Root cause:** What specifically caused the spike (attack, deployment, config change, bug).
3. **Impact:** Were real users affected? For how long? What was the peak rejection rate?
4. **Detection:** Did our alerts catch this promptly? Should thresholds be adjusted?
5. **Resolution:** What actions resolved the issue?
6. **Action items** (examples):
   - Tune alert thresholds in `prometheus/alert-rules.yml` if too noisy or too slow.
   - Add rate limiting if the spike was caused by an external attack.
   - Improve rejection pattern regexes if false positives/negatives were identified.
   - Add a `RejectionRateSpike` alert for individual reasons (e.g., `prompt_injection` specifically) if the current aggregate alert was too coarse.
   - Consider adding an alert on the `agent_rejection_pattern_total` metric for specific high-risk patterns.
   - Update this runbook with anything that would have helped during the incident.

---

## Quick Reference: Key Commands

### Production (Kubernetes)

| Action                   | Command                                                                                |
| ------------------------ | -------------------------------------------------------------------------------------- |
| Pod status               | `kubectl get pods -l app=agent-api`                                                    |
| Deployment status        | `kubectl get deployment agent-api`                                                     |
| Describe deployment      | `kubectl describe deployment agent-api`                                                |
| API logs (last 100)      | `kubectl logs -l app=agent-api --tail=100`                                             |
| Previous crash logs      | `kubectl logs <pod-name> --previous`                                                   |
| Traffic generator logs   | `kubectl logs -l app=traffic-generator --tail=50`                                      |
| Check PROMPT_VERSION     | `kubectl exec deploy/agent-api -- env \| grep PROMPT_VERSION`                          |
| Current image tag        | `kubectl get deploy agent-api -o jsonpath='{.spec.template.spec.containers[0].image}'` |
| Port-forward API         | `kubectl port-forward svc/agent-api 8080:8080`                                         |
| Check API health         | `curl -s http://localhost:8080/healthz \| jq .` (after port-forward)                   |
| View raw metrics         | `curl -s http://localhost:8080/metrics \| grep agent_rejections` (after port-forward)  |
| Restart API              | `kubectl rollout restart deploy/agent-api`                                             |
| Rollback API             | `kubectl rollout undo deployment/agent-api`                                            |
| Scale down traffic       | `kubectl scale deploy/traffic-generator --replicas=0`                                  |
| Scale down API           | `kubectl scale deploy/agent-api --replicas=0`                                          |
| Restore API (2 replicas) | `kubectl scale deploy/agent-api --replicas=2`                                          |
| Pod resource usage       | `kubectl top pods -l app=agent-api`                                                    |
| Rollout history          | `kubectl rollout history deployment/agent-api`                                         |
| Open Prometheus          | `kubectl port-forward svc/prometheus 9090:9090` → `http://localhost:9090`              |
| Open Grafana             | `kubectl port-forward svc/grafana 3000:3000` → `http://localhost:3000` (admin/admin)   |

### Local Development (Docker Compose)

| Action              | Command                                         |
| ------------------- | ----------------------------------------------- |
| Check API health    | `curl -s http://localhost:8080/healthz \| jq .` |
| Container status    | `docker compose ps`                             |
| API logs (last 100) | `docker compose logs --tail=100 agent-api`      |
| Restart API         | `docker compose restart agent-api`              |
| Stop traffic        | `docker compose stop traffic-generator`         |
| Full stack restart  | `docker compose down && make up`                |
| Run eval suite      | `make eval`                                     |
| Test single request | `make test-ask`                                 |
| Test rejection      | `make test-reject`                              |

## Key Metrics Reference

| Metric                               | Description                              | Normal Value                  |
| ------------------------------------ | ---------------------------------------- | ----------------------------- |
| `agent_requests_total{route="/ask"}` | Total requests to /ask                   | Steady rate                   |
| `agent_rejections_total`             | Total rejections (by reason, pattern_id) | ~15% of traffic               |
| `agent_accepted_total`               | Total accepted requests                  | ~85% of traffic               |
| `agent_rejection_pattern_total`      | Per-pattern rejection counts             | Distributed across categories |
| `agent_http_responses_total`         | HTTP status codes                        | Mostly 200s                   |
| `agent_exceptions_total`             | Unhandled exceptions                     | 0                             |
| `agent_request_latency_seconds`      | Request latency histogram                | Low ms range                  |
| `agent_message_length_bytes`         | Input message size distribution          | Varies                        |
