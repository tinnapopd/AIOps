import os
import re
import time
from flask import Flask, request, jsonify
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

PROMPT_VERSION = os.environ.get('PROMPT_VERSION', 'v1.0.0')

# Prometheus metrics
REQUEST_COUNT = Counter(
    'agent_requests_total',
    'Total number of requests to the agent API',
    ['prompt_version', 'route']
)

# TODO: How would you track rejection metrics for observability?
# Consider: What information would operators need when debugging rejection spikes?

REQUEST_LATENCY = Histogram(
    'agent_request_latency_seconds',
    'Request latency in seconds',
    ['prompt_version', 'route'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

# Rejection patterns - deterministic classification based on message content
REJECTION_PATTERNS = {
    'prompt_injection': [
        r'ignore\s+(all\s+)?(previous\s+)?instructions',
        r'system\s+prompt',
        r'disregard\s+(all\s+)?(previous\s+)?',
        r'forget\s+(all\s+)?(previous\s+)?instructions',
        r'new\s+instructions',
        r'override\s+(all\s+)?rules',
        r'jailbreak',
        r'bypass\s+(safety|filter|restriction)',
    ],
    'secrets_request': [
        r'password',
        r'api[\s_-]?key',
        r'secret[\s_-]?key',
        r'access[\s_-]?token',
        r'private[\s_-]?key',
        r'credentials',
        r'auth[\s_-]?token',
        r'bearer[\s_-]?token',
    ],
    'dangerous_action': [
        r'restart\s+prod',
        r'delete\s+(the\s+)?database',
        r'drop\s+table',
        r'rm\s+-rf',
        r'shutdown\s+server',
        r'execute\s+command',
        r'run\s+as\s+root',
        r'sudo\s+',
        r'format\s+(hard\s+)?drive',
        r'wipe\s+(all\s+)?data',
    ],
}


def classify_rejection(message: str) -> tuple[bool, str | None]:
    """
    Classify whether a message should be rejected and return the reason.
    Returns (rejected, reason) tuple.
    """
    message_lower = message.lower()
    
    for reason, patterns in REJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, message_lower):
                return True, reason
    
    return False, None


def generate_response(message: str) -> str:
    """Generate a simple response for accepted messages."""
    responses = [
        f"I understand you're asking about: {message[:50]}...",
        "That's an interesting question. Let me help you with that.",
        "I'd be happy to assist with your request.",
        "Thank you for your question. Here's what I can tell you.",
    ]
    return responses[hash(message) % len(responses)]


@app.route('/ask', methods=['POST'])
def ask():
    """
    Main endpoint for asking the agent.
    Accepts JSON with 'message' field.
    Returns rejection status, reason, prompt version, and answer.
    """
    start_time = time.time()
    
    REQUEST_COUNT.labels(prompt_version=PROMPT_VERSION, route='/ask').inc()
    
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({
                'error': 'Missing required field: message',
                'rejected': True,
                'reason': 'invalid_request',
                'prompt_version': PROMPT_VERSION,
                'answer': None
            }), 400
        
        message = data['message']
        rejected, reason = classify_rejection(message)
        
        if rejected:
            # TODO: Implement rejection tracking here
            response = {
                'rejected': True,
                'reason': reason,
                'prompt_version': PROMPT_VERSION,
                'answer': f"I cannot process this request due to: {reason}"
            }
        else:
            response = {
                'rejected': False,
                'reason': None,
                'prompt_version': PROMPT_VERSION,
                'answer': generate_response(message)
            }
        
        return jsonify(response), 200
    
    finally:
        latency = time.time() - start_time
        REQUEST_LATENCY.labels(prompt_version=PROMPT_VERSION, route='/ask').observe(latency)


@app.route('/healthz', methods=['GET'])
def healthz():
    """Health check endpoint."""
    REQUEST_COUNT.labels(prompt_version=PROMPT_VERSION, route='/healthz').inc()
    return jsonify({
        'status': 'healthy',
        'prompt_version': PROMPT_VERSION
    }), 200


@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint."""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
