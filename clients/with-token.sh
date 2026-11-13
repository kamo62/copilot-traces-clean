#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
token_file=${COPILOT_TRACES_TOKEN_FILE:-"$root/.otlp-token"}

if [ ! -r "$token_file" ]; then
  echo "Token file is not readable; set COPILOT_TRACES_TOKEN_FILE to a private token file." >&2
  exit 1
fi

token=$(cat "$token_file")
if [ -z "$token" ]; then
  echo "Token file is empty." >&2
  exit 1
fi

export OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT:-http://127.0.0.1:14328}
export OTEL_EXPORTER_OTLP_PROTOCOL=${OTEL_EXPORTER_OTLP_PROTOCOL:-http/json}
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer $token"
export COPILOT_OTEL_ENABLED=true
export COPILOT_OTEL_EXPORTER_TYPE=otlp-http
export OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
unset token

if [ "$#" -eq 0 ]; then
  echo "Usage: clients/with-token.sh copilot [args...] | code [args...]" >&2
  exit 2
fi

exec "$@"
