# agentgate - agent-native MCP authorization gateway
# Build:  docker build -t agentgate .
# Run:    docker run --rm -v $(pwd)/policies:/app/policies -v agentgate-state:/app/.agentgate \
#           agentgate run --config /app/policies/example.yaml --agent claude-code

FROM python:3.12-slim AS base

# non-root user; state and policies live on volumes
RUN useradd --create-home --shell /usr/sbin/nologin agentgate
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && pip cache purge

USER agentgate

# default: stdio gateway; override command for ui/http
ENTRYPOINT ["agentgate"]
CMD ["run", "--help"]
