#!/bin/bash
# Boot Ollama and make sure the model PhishBrain is configured to use is present.
#
# The name comes from OLLAMA_MODEL so this script and the backend cannot
# disagree: pulling llama3.1 while the backend asked for llama3.2:3b (or the
# reverse) left every scan without a model verdict, reported only as
# "the model did not answer within the scan deadline".
set -u

MODEL="${OLLAMA_MODEL:-llama3.2:3b}"

ollama serve &
OLLAMA_PID=$!

# Wait for the API instead of sleeping a fixed five seconds: on a slow first
# boot the pull used to start before the server was listening.
for _ in $(seq 1 60); do
  if ollama list >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "Ensuring ${MODEL} is available (first boot downloads it)..."
if ollama pull "${MODEL}"; then
  echo "Model ${MODEL} ready, keeping Ollama running..."
else
  echo "WARNING: could not pull ${MODEL}; scans will fall back to the deterministic assessment." >&2
fi

wait "$OLLAMA_PID"
