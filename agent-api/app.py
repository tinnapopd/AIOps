import os
import re
import time
from flask import Flask, request, jsonify
from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

app = Flask(__name__)

PROMPT_VERSION = os.environ.get("PROMPT_VERSION", "v1.0.0")

# Prometheus Metrics
# Each metric answers a specific operational question:
#   - Is the system healthy?
#   - Are users being impacted?
#   - Are we under attack?
#   - Did a deployment break something?

# Traffic and Throughput Metrics
REQUEST_COUNT = Counter(
    "agent_requests_total",
    "Total number of requests to the agent API",
    ["prompt_version", "route"],
)

# Success / Acceptance Metrics
ACCEPTED_COUNT = Counter(
    "agent_accepted_total",
    "Total number of accepted requests",
    ["prompt_version", "route"],
)

# Rejection Metrics
# TODO: How would you track rejection metrics for observability?
# Consider: What information would operators need when debugging rejection spikes?
REJECTION_COUNT = Counter(
    "agent_rejections_total",
    "Total number of requests rejected by the agent API",
    ["prompt_version", "reason", "pattern_id"],
)

# Pattern-level rejection metrics
REJECTION_PATTERN_COUNT = Counter(
    "agent_rejection_pattern_total",
    "Total number of times a specific rejection pattern matched",
    ["prompt_version", "reason", "pattern_id"],
)

# HTTP Response Codes
HTTP_STATUS_COUNT = Counter(
    "agent_http_responses_total",
    "HTTP responses by status code",
    ["route", "status_code"],
)

# Exception Tracking
EXCEPTION_COUNT = Counter(
    "agent_exceptions_total",
    "Total number of unhandled exceptions",
    ["route"],
)

# Latency Monitoring
REQUEST_LATENCY = Histogram(
    "agent_request_latency_seconds",
    "Request latency in seconds",
    ["prompt_version", "route", "outcome"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# Input Size Distribution
MESSAGE_LENGTH = Histogram(
    "agent_message_length_bytes",
    "Length of input message in bytes",
    ["prompt_version"],
    buckets=[10, 50, 100, 250, 500, 1000, 2000, 5000],
)

# Rejection patterns - deterministic classification based on message content
REJECTION_PATTERNS = {
    "prompt_injection": [
        (r"ignore\s+(all\s+)?(previous\s+)?instructions", "pi_1"),
        (r"system\s+prompt", "pi_2"),
        (r"disregard\s+(all\s+)?(previous\s+)?", "pi_3"),
        (r"forget\s+(all\s+)?(previous\s+)?instructions", "pi_4"),
        (r"new\s+instructions", "pi_5"),
        (r"override\s+(all\s+)?rules", "pi_6"),
        (r"jailbreak", "pi_7"),
        (r"bypass\s+(safety|filter|restriction)", "pi_8"),
    ],
    "secrets_request": [
        (r"password", "sr_1"),
        (r"api[\s_-]?key", "sr_2"),
        (r"secret[\s_-]?key", "sr_3"),
        (r"access[\s_-]?token", "sr_4"),
        (r"private[\s_-]?key", "sr_5"),
        (r"credentials", "sr_6"),
        (r"auth[\s_-]?token", "sr_7"),
        (r"bearer[\s_-]?token", "sr_8"),
    ],
    "dangerous_action": [
        (r"restart\s+prod", "da_1"),
        (r"delete\s+(the\s+)?database", "da_2"),
        (r"drop\s+table", "da_3"),
        (r"rm\s+-rf", "da_4"),
        (r"shutdown\s+server", "da_5"),
        (r"execute\s+command", "da_6"),
        (r"run\s+as\s+root", "da_7"),
        (r"sudo\s+", "da_8"),
        (r"format\s+(hard\s+)?drive", "da_9"),
        (r"wipe\s+(all\s+)?data", "da_10"),
    ],
}


def classify_rejection(message: str) -> tuple[bool, str | None, str | None]:
    """
    Classify whether a message should be rejected and return the reason and pattern_id.
    Returns (rejected, reason, pattern_id) tuple.
    """
    message_lower = message.lower()

    for reason, patterns in REJECTION_PATTERNS.items():
        for pattern, pattern_id in patterns:
            if re.search(pattern, message_lower):
                return True, reason, pattern_id

    return False, None, None


def generate_response(message: str) -> str:
    """Generate a simple response for accepted messages."""
    responses = [
        f"I understand you're asking about: {message[:50]}...",
        "That's an interesting question. Let me help you with that.",
        "I'd be happy to assist with your request.",
        "Thank you for your question. Here's what I can tell you.",
    ]
    return responses[hash(message) % len(responses)]


@app.route("/ask", methods=["POST"])
def ask():
    """
    Main endpoint for asking the agent.
    Accepts JSON with 'message' field.
    Returns rejection status, reason, prompt version, and answer.
    """
    route = "/ask"
    outcome = "error"

    start_time = time.time()
    REQUEST_COUNT.labels(prompt_version=PROMPT_VERSION, route=route).inc()

    try:
        data = request.get_json()
        if not data or "message" not in data:
            REJECTION_COUNT.labels(
                prompt_version=PROMPT_VERSION,
                reason="invalid_request",
                pattern_id="none",
            ).inc()

            HTTP_STATUS_COUNT.labels(route=route, status_code="400").inc()

            outcome = "rejected"
            return jsonify(
                {
                    "error": "Missing required field: message",
                    "rejected": True,
                    "reason": "invalid_request",
                    "prompt_version": PROMPT_VERSION,
                    "answer": None,
                }
            ), 400

        message = data["message"]
        MESSAGE_LENGTH.labels(prompt_version=PROMPT_VERSION).observe(
            amount=len(message.encode("utf-8"))
        )
        rejected, reason, pattern_id = classify_rejection(message)

        if rejected:
            # TODO: Implement rejection tracking here
            REJECTION_COUNT.labels(
                prompt_version=PROMPT_VERSION,
                reason=reason,
                pattern_id=pattern_id,
            ).inc()

            REJECTION_PATTERN_COUNT.labels(
                prompt_version=PROMPT_VERSION,
                reason=reason,
                pattern_id=pattern_id,
            ).inc()

            outcome = "rejected"
            response = {
                "rejected": True,
                "reason": reason,
                "prompt_version": PROMPT_VERSION,
                "answer": f"I cannot process this request due to: {reason}",
            }
        else:
            ACCEPTED_COUNT.labels(
                prompt_version=PROMPT_VERSION,
                route=route,
            ).inc()

            outcome = "accepted"
            response = {
                "rejected": False,
                "reason": None,
                "prompt_version": PROMPT_VERSION,
                "answer": generate_response(message),
            }

        HTTP_STATUS_COUNT.labels(route=route, status_code="200").inc()
        return jsonify(response), 200

    except Exception:
        EXCEPTION_COUNT.labels(route=route).inc()
        HTTP_STATUS_COUNT.labels(route=route, status_code="500").inc()
        raise

    finally:
        latency = time.time() - start_time
        REQUEST_LATENCY.labels(
            prompt_version=PROMPT_VERSION,
            route=route,
            outcome=outcome,
        ).observe(latency)


@app.route("/healthz", methods=["GET"])
def healthz():
    """Health check endpoint."""
    route = "/healthz"
    REQUEST_COUNT.labels(prompt_version=PROMPT_VERSION, route=route).inc()
    HTTP_STATUS_COUNT.labels(route=route, status_code="200").inc()
    return jsonify(
        {"status": "healthy", "prompt_version": PROMPT_VERSION}
    ), 200


@app.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus metrics endpoint."""
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec B104 - bind all interfaces required for container networking
