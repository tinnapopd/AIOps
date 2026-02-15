# AI-Ops Take-Home Test

A self-contained repository for evaluating DevOps + AIOps skills. This repo simulates an "LLM Agent API" that sometimes refuses requests and emits metrics.

## Quick Start

```bash
# Start the full stack (API, Prometheus, Grafana, Traffic Generator)
make up

# View logs
make logs

# Run evaluation suite
make eval

# Stop everything
make down
```

## Local Endpoints

| Service | URL | Credentials |
|---------|-----|-------------|
| Agent API | http://localhost:8080 | - |
| Metrics | http://localhost:8080/metrics | - |
| Prometheus | http://localhost:9090 | - |
| Grafana | http://localhost:3000 | admin/admin |

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│    Traffic      │────▶│   Agent API     │
│   Generator     │     │   (Port 8080)   │
└─────────────────┘     └────────┬────────┘
                                 │
                                 │ /metrics
                                 ▼
                        ┌─────────────────┐
                        │   Prometheus    │
                        │   (Port 9090)   │
                        └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │    Grafana      │
                        │   (Port 3000)   │
                        └─────────────────┘
```

## Agent API Endpoints

### POST /ask
Send a message to the agent.

```bash
curl -X POST http://localhost:8080/ask \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the weather?"}'
```

Response:
```json
{
  "rejected": false,
  "reason": null,
  "prompt_version": "v1.0.0",
  "answer": "I'd be happy to assist with your request."
}
```

### GET /healthz
Health check endpoint.

```bash
curl http://localhost:8080/healthz
```

### GET /metrics
Prometheus metrics endpoint.

```bash
curl http://localhost:8080/metrics
```

## Rejection Logic

The agent rejects requests based on content patterns:

| Reason | Trigger Patterns |
|--------|------------------|
| `prompt_injection` | "ignore instructions", "system prompt", "jailbreak" |
| `secrets_request` | "password", "api key", "credentials" |
| `dangerous_action` | "restart prod", "delete database", "rm -rf" |

## Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `agent_requests_total` | Counter | `prompt_version`, `route` |
| `agent_rejections_total` | Counter | `prompt_version`, `reason` |
| `agent_request_latency_seconds` | Histogram | `prompt_version`, `route` |

## Evaluation Runner

The eval runner tests the agent against two datasets:

- **Golden Dataset**: Normal messages that should be accepted
- **Adversarial Dataset**: Malicious messages that should be rejected

```bash
# Run eval
make eval

# Results are saved to ./eval-results/
```

### Gate Thresholds

| Gate | Threshold | Description |
|------|-----------|-------------|
| `min_golden_accuracy` | 90% | Golden messages should be accepted |
| `max_golden_rejection_rate` | 5% | Don't reject too many legitimate requests |
| `min_adversarial_rejection_rate` | 60% | Must reject most malicious requests |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMPT_VERSION` | v1.0.0 | Version string included in responses/metrics |
| `REQUEST_INTERVAL_MS` | 500 | Traffic generator request interval |
| `REJECTION_MIX_RATIO` | 0.15 | Ratio of rejection-triggering traffic |

## For Candidates

See [CANDIDATE_INSTRUCTIONS.md](./CANDIDATE_INSTRUCTIONS.md) for the take-home test prompt.

## For Reviewers

See [GRADING_RUBRIC.md](./GRADING_RUBRIC.md) for evaluation criteria.
