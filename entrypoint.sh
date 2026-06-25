#!/bin/sh
# GuardrailProbe container entrypoint.
#
# Checks whether host-installed ML packages (LlamaFirewall, LLM Guard) have
# been mounted into /app/site-packages.  If they are present AND compiled for
# the same Python version as the container, adds the directory to PYTHONPATH
# so that the adapters can import them.
#
# If the .so files were compiled for a different Python version the directory
# is NOT added to PYTHONPATH — adding it would corrupt numpy, pydantic-core,
# and other packages that ship compiled C extensions.
#
# Install on the host using the SAME Python version as the container (3.12):
#   python3.12 -m pip install llamafirewall llm-guard --target ./site-packages
#   docker compose up

set -e

SP="/app/site-packages"

if [ -d "$SP" ] && [ "$(ls -A "$SP" 2>/dev/null)" ]; then
    # Detect the Python ABI tag this container uses (e.g. cpython-312)
    PYABI=$(python -c "import sys; print('cpython-{}{}'.format(sys.version_info.major, sys.version_info.minor))")

    # Look for any .so compiled for a DIFFERENT Python version.
    # Python .so naming: <module>.cpython-312-x86_64-linux-gnu.so (hyphen after ABI).
    # First find files that carry a cpython-NNN version tag, then exclude our version.
    INCOMPAT=$(find "$SP" -maxdepth 4 \
        -name "*.cpython-[0-9][0-9][0-9]-*.so" \
        ! -name "*${PYABI}*" \
        -not -path "*/\.*" \
        2>/dev/null | head -1)

    if [ -n "$INCOMPAT" ]; then
        echo "[guardrailprobe] WARNING: site-packages contain C extensions built for a different Python."
        echo "[guardrailprobe]   Found : $(basename "$INCOMPAT")"
        echo "[guardrailprobe]   Needs : ${PYABI}"
        echo "[guardrailprobe] Adding these packages to PYTHONPATH would corrupt numpy, pydantic-core,"
        echo "[guardrailprobe] and other dependencies. site-packages will NOT be added."
        echo "[guardrailprobe]"
        echo "[guardrailprobe] Fix: re-install using the container's Python version:"
        echo "[guardrailprobe]   rm -rf ./site-packages"
        echo "[guardrailprobe]   python3.12 -m pip install llamafirewall llm-guard --target ./site-packages --ignore-installed"
        echo "[guardrailprobe]   docker compose up"
    else
        # Compatible — append so Docker's own packages still take priority
        # for anything installed in both places.
        export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}${SP}"

        lf=$(python -c "
import sys, importlib.util
sys.path.append('$SP')
print('YES' if importlib.util.find_spec('llamafirewall') else 'NO')
" 2>/dev/null || echo NO)

        lg=$(python -c "
import sys, importlib.util
sys.path.append('$SP')
print('YES' if importlib.util.find_spec('llm_guard') else 'NO')
" 2>/dev/null || echo NO)

        echo "[guardrailprobe] site-packages mounted (${PYABI}) — llama_firewall: ${lf}  llm_guard: ${lg}"
    fi
else
    echo "[guardrailprobe] site-packages empty — llama_firewall and llm_guard adapters disabled"
    echo "[guardrailprobe] To enable: python3.12 -m pip install llamafirewall llm-guard --target ./site-packages --ignore-installed"
fi

exec "$@"
