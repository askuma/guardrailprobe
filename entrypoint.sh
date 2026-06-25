#!/bin/sh
# GuardrailProbe container entrypoint.
#
# Checks whether host-installed ML packages (LlamaFirewall, LLM Guard) have
# been mounted into /app/site-packages.  If they are present, adds the
# directory to PYTHONPATH before starting the app so that the adapters can
# import them.  An empty or absent directory is silently ignored.
#
# Install on the host, then restart the container:
#   pip install llamafirewall llm-guard --target ./site-packages
#   docker compose up

set -e

SP="/app/site-packages"

if [ -d "$SP" ] && [ "$(ls -A "$SP" 2>/dev/null)" ]; then
    export PYTHONPATH="${SP}${PYTHONPATH:+:$PYTHONPATH}"

    lf=$(python -c "
import sys, importlib.util
sys.path.insert(0, '$SP')
print('YES' if importlib.util.find_spec('llamafirewall') else 'NO')
" 2>/dev/null || echo NO)

    lg=$(python -c "
import sys, importlib.util
sys.path.insert(0, '$SP')
print('YES' if importlib.util.find_spec('llm_guard') else 'NO')
" 2>/dev/null || echo NO)

    echo "[guardrailprobe] site-packages mounted — llama_firewall: ${lf}  llm_guard: ${lg}"
else
    echo "[guardrailprobe] site-packages empty — llama_firewall and llm_guard adapters disabled"
    echo "[guardrailprobe] To enable: pip install llamafirewall llm-guard --target ./site-packages"
fi

exec "$@"
