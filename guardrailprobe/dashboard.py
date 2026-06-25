"""
GuardrailProbe probe-builder dashboard.

Flask web UI served at localhost:8080 by ``guardrailprobe dashboard``.

Routes
------
GET  /                  — probe builder home page
GET  /api/backends      — JSON list of adapters + credential status
GET  /api/probes        — JSON probe library (filterable by category/severity)
POST /api/probe/run     — run a single ad-hoc payload against one backend
POST /api/benchmark/run — trigger a full comparison run
GET  /api/benchmark/latest — return the latest benchmark JSON
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory
from jinja2 import DictLoader


# ── Embedded HTML templates ───────────────────────────────────────────────────

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GuardrailProbe Dashboard</title>
  <style>
    :root {
      --bg: #0f172a; --card: #1e293b; --border: #334155;
      --accent: #38bdf8; --text: #e2e8f0; --muted: #94a3b8;
      --green: #10b981; --red: #ef4444; --amber: #f59e0b;
      --font: ui-sans-serif, system-ui, -apple-system, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--font);
           min-height: 100vh; padding: 24px; }
    header { display: flex; align-items: center; gap: 12px; margin-bottom: 32px; }
    header h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    header .badge { background: var(--accent); color: #0f172a; font-size: 0.7rem;
                    font-weight: 700; padding: 2px 8px; border-radius: 999px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
    .card { background: var(--card); border: 1px solid var(--border);
            border-radius: 12px; padding: 20px; }
    .card h2 { font-size: 0.875rem; font-weight: 600; text-transform: uppercase;
               letter-spacing: 0.05em; color: var(--muted); margin-bottom: 16px; }
    label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 4px; }
    input, select, textarea {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; padding: 8px 10px; color: var(--text);
      font-family: var(--font); font-size: 0.875rem; margin-bottom: 12px;
    }
    textarea { resize: vertical; min-height: 100px; }
    button {
      background: var(--accent); color: #0f172a; border: none; border-radius: 6px;
      padding: 8px 16px; font-weight: 600; cursor: pointer; font-size: 0.875rem;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    button.secondary {
      background: var(--border); color: var(--text);
    }
    .result-box {
      background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
      padding: 14px; margin-top: 12px; font-family: monospace; font-size: 0.8rem;
      white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto;
      min-height: 60px; color: var(--muted);
    }
    .pill {
      display: inline-block; border-radius: 999px; padding: 2px 8px;
      font-size: 0.75rem; font-weight: 600;
    }
    .pill.green  { background: #064e3b; color: var(--green); }
    .pill.red    { background: #450a0a; color: var(--red); }
    .pill.amber  { background: #451a03; color: var(--amber); }
    .pill.gray   { background: var(--border); color: var(--muted); }
    table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
    th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; text-transform: uppercase;
         font-size: 0.7rem; letter-spacing: 0.05em; }
    #adapters-table td:nth-child(2) { text-align: center; }
    .spinner { border: 3px solid var(--border); border-top: 3px solid var(--accent);
               border-radius: 50%; width: 20px; height: 20px;
               animation: spin 0.7s linear infinite; display: inline-block; }
    @keyframes spin { to { transform: rotate(360deg); } }
    footer { margin-top: 40px; text-align: center; color: var(--muted); font-size: 0.75rem; }
    footer a { color: var(--accent); text-decoration: none; }
  </style>
</head>
<body>
  <header>
    <h1>GuardrailProbe</h1>
    <span class="badge">v{{ version }}</span>
  </header>

  <div class="grid">

    <!-- Adapter status card -->
    <div class="card">
      <h2>Adapter Status</h2>
      <table id="adapters-table">
        <thead><tr><th>Backend</th><th>Ready</th><th>Note</th></tr></thead>
        <tbody id="adapter-rows">
          <tr><td colspan="3"><span class="spinner"></span></td></tr>
        </tbody>
      </table>
    </div>

    <!-- Ad-hoc probe card -->
    <div class="card">
      <h2>Run a Probe</h2>
      <label>Backend</label>
      <select id="probe-backend"></select>
      <label>Payload</label>
      <textarea id="probe-payload" placeholder="Enter a prompt to test…"></textarea>
      <button id="probe-btn">Run Probe</button>
      <div class="result-box" id="probe-result">Result will appear here.</div>
    </div>

    <!-- Full benchmark card -->
    <div class="card">
      <h2>Run Full Benchmark</h2>
      <label>Year</label>
      <input type="number" id="bench-year" min="2024" max="2030">
      <label>Month (1–12)</label>
      <input type="number" id="bench-month" min="1" max="12">
      <label>Backends (comma-separated, leave blank for all)</label>
      <input type="text" id="bench-backends" placeholder="e.g. guardrails_ai,presidio">
      <button id="bench-btn">Start Benchmark</button>
      <div class="result-box" id="bench-result">Benchmark output will appear here.</div>
    </div>

    <!-- Latest benchmark summary -->
    <div class="card">
      <h2>Latest Benchmark</h2>
      <div id="latest-summary" class="result-box">Loading…</div>
      <button class="secondary" id="refresh-btn" style="margin-top:12px">Refresh</button>
    </div>

  </div>

  <footer>
    <p>GuardrailProbe — independent AI guardrail benchmarking tool &bull;
       <a href="https://github.com/askuma/guardrailprobe">GitHub</a></p>
  </footer>

  <script>
    const $ = id => document.getElementById(id);

    function pill(text, cls) {
      return `<span class="pill ${cls}">${text}</span>`;
    }

    async function loadAdapters() {
      const res = await fetch('/api/backends');
      const data = await res.json();
      const tbody = $('adapter-rows');
      const select = $('probe-backend');
      tbody.innerHTML = '';
      select.innerHTML = '';
      data.forEach(b => {
        const ready = b.ready;
        const badgeCls = ready ? 'green' : (b.status.includes('no_llm') ? 'amber' : 'red');
        const badgeLabel = ready ? 'YES' : 'NO';
        tbody.innerHTML += `<tr>
          <td>${b.backend}</td>
          <td>${pill(badgeLabel, badgeCls)}</td>
          <td style="color:var(--muted);font-size:0.75rem">${b.message || ''}</td>
        </tr>`;
        const opt = document.createElement('option');
        opt.value = b.backend;
        opt.textContent = b.backend + (ready ? '' : ' (not ready)');
        if (!ready) opt.disabled = true;
        select.appendChild(opt);
      });
    }

    async function runProbe() {
      const backend = $('probe-backend').value;
      const payload = $('probe-payload').value.trim();
      if (!payload) { alert('Enter a payload first.'); return; }
      $('probe-result').textContent = 'Running…';
      $('probe-btn').disabled = true;
      try {
        const res = await fetch('/api/probe/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({backend, payload}),
        });
        const data = await res.json();
        $('probe-result').textContent = JSON.stringify(data, null, 2);
      } catch(e) {
        $('probe-result').textContent = 'Error: ' + e.message;
      }
      $('probe-btn').disabled = false;
    }

    async function runBenchmark() {
      const year = parseInt($('bench-year').value) || new Date().getFullYear();
      const month = parseInt($('bench-month').value) || (new Date().getMonth() + 1);
      const backends = $('bench-backends').value.trim();
      $('bench-result').textContent = 'Running benchmark (this may take several minutes)…';
      $('bench-btn').disabled = true;
      try {
        const res = await fetch('/api/benchmark/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({year, month, backends: backends || null, dry_run: false}),
        });
        const data = await res.json();
        $('bench-result').textContent = JSON.stringify(data, null, 2);
      } catch(e) {
        $('bench-result').textContent = 'Error: ' + e.message;
      }
      $('bench-btn').disabled = false;
    }

    async function loadLatest() {
      try {
        const res = await fetch('/api/benchmark/latest');
        const data = await res.json();
        if (!data || data.error) {
          $('latest-summary').textContent = 'No benchmark data available yet.';
          return;
        }
        const meta = data.metadata || {};
        const results = data.results || {};
        let text = `Run ID: ${meta.run_id || 'N/A'}\\n`;
        text += `Generated: ${meta.generated_at || 'N/A'}\\n`;
        text += `Backends tested: ${(meta.backends_tested || []).join(', ') || 'none'}\\n\\n`;
        if (results.best_overall) text += `Best overall: ${results.best_overall}\\n`;
        const sums = results.backend_summaries || {};
        for (const [b, s] of Object.entries(sums)) {
          text += `  ${b.padEnd(22)} ${(s.pass_rate * 100).toFixed(1)}%  (${s.passed}/${s.total_probes})\\n`;
        }
        $('latest-summary').textContent = text;
      } catch(e) {
        $('latest-summary').textContent = 'Could not load latest benchmark.';
      }
    }

    // Set date defaults
    const now = new Date();
    $('bench-year').value = now.getFullYear();
    $('bench-month').value = now.getMonth() + 1;

    $('probe-btn').addEventListener('click', runProbe);
    $('bench-btn').addEventListener('click', runBenchmark);
    $('refresh-btn').addEventListener('click', loadLatest);

    loadAdapters();
    loadLatest();
  </script>
</body>
</html>
"""


# ── Flask app factory ─────────────────────────────────────────────────────────


def create_app() -> Flask:
    """Create and configure the GuardrailProbe Flask dashboard app."""
    import guardrailprobe

    app = Flask(__name__, template_folder=None)
    app.jinja_env.loader = DictLoader({"index.html": _INDEX_HTML})

    _benchmark_lock = threading.Lock()

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.get("/")
    def index():
        from flask import render_template_string
        return render_template_string(_INDEX_HTML, version=guardrailprobe.__version__)

    @app.get("/api/backends")
    def api_backends():
        from guardrailprobe.adapters import REGISTRY
        return jsonify(REGISTRY.status_report())

    @app.get("/api/probes")
    def api_probes():
        from guardrailprobe.probes import ProbeLibrary
        lib = ProbeLibrary()
        category  = request.args.get("category")
        severity  = request.args.get("severity")
        owasp_ref = request.args.get("owasp_ref")

        probes = lib.all_probes()
        if category:
            probes = [p for p in probes if p.category.value == category]
        if severity:
            probes = [p for p in probes if p.severity == severity]
        if owasp_ref:
            probes = [p for p in probes if p.owasp_ref == owasp_ref]

        return jsonify([
            {
                "id": p.id,
                "category": p.category.value,
                "owasp_ref": p.owasp_ref,
                "severity": p.severity,
                "description": p.description,
                "expected_action": p.expected_action.value,
                "tags": p.tags,
            }
            for p in probes
        ])

    @app.post("/api/probe/run")
    def api_probe_run():
        body = request.get_json(force=True)
        backend_name = body.get("backend", "")
        payload      = body.get("payload", "")

        if not payload:
            return jsonify({"error": "payload is required"}), 400

        from guardrailprobe.adapters import REGISTRY
        adapter = REGISTRY.get(backend_name)
        if adapter is None:
            return jsonify({"error": f"Unknown backend: {backend_name!r}"}), 404

        try:
            resp = adapter.run_probe(payload)
            return jsonify({
                "backend":     resp.backend,
                "action":      resp.action.value,
                "latency_ms":  resp.latency_ms,
                "status":      resp.status.value,
                "message":     resp.status_message,
                "raw_response": resp.raw_response,
                "timestamp":   resp.timestamp,
            })
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.post("/api/benchmark/run")
    def api_benchmark_run():
        with _benchmark_lock:
            body      = request.get_json(force=True)
            year      = body.get("year") or datetime.now(timezone.utc).year
            month     = body.get("month") or datetime.now(timezone.utc).month
            dry_run   = bool(body.get("dry_run", False))
            backends  = body.get("backends")  # comma-separated string or None

            from guardrailprobe._types import GuardrailBackend
            from guardrailprobe.report import BenchmarkRunner

            backend_list = None
            if backends:
                try:
                    backend_list = [
                        GuardrailBackend(b.strip())
                        for b in backends.split(",")
                        if b.strip()
                    ]
                except ValueError as exc:
                    return jsonify({"error": f"Invalid backend: {exc}"}), 400

            runner = BenchmarkRunner()
            try:
                arts = runner.generate_monthly_benchmark(
                    year=year, month=month,
                    backends=backend_list, dry_run=dry_run,
                )
            except Exception as exc:
                return jsonify({"error": str(exc)}), 500

            return jsonify({
                "run_id":           arts.run_id,
                "json_path":        arts.json_path,
                "markdown_path":    arts.markdown_path,
                "pdf_path":         arts.pdf_path,
                "backends_tested":  arts.backends_tested,
                "backends_skipped": arts.backends_skipped,
                "probe_count":      arts.probe_count,
            })

    @app.get("/api/benchmark/latest")
    def api_benchmark_latest():
        from guardrailprobe.report import BenchmarkRunner
        runner = BenchmarkRunner()
        data = runner.get_latest_benchmark()
        if data is None:
            return jsonify({"error": "No benchmark data available"}), 404
        return jsonify(data)

    @app.get("/api/benchmark/list")
    def api_benchmark_list():
        from guardrailprobe.report import BenchmarkRunner
        runner = BenchmarkRunner()
        return jsonify(runner.list_all_benchmarks())

    return app
