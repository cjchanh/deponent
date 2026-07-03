#!/usr/bin/env python3
"""
governed_team.py — a governed local agent team built on Deponent.

Three agents (one shared local model):
  Architect : writes the acceptance test (the bar for "done").
  Builder   : tool-loops to green — BUT every tool call passes through a Deponent
              Cell (deny-by-default gate + Seatbelt jail), and every decision is
              appended to a tamper-evident ledger (the testimony).
  Reviewer  : an independent CLEAN/BLOCKED verdict (advisory).

Closure is NOT the Builder saying "done" — it is (a) an out-of-band pytest re-run,
(b) an intact hash chain of every governed action, and (c) a rogue action proven
blocked. Self-reported health is never the evidence.

This example shows the governance kernel is independent of the reasoning core: run
it on a local MLX model (Apple Silicon) or any tool-capable Ollama model. The Cell
does not change when the model does.

Run (Ollama, any tool-capable coder):
    python3 examples/governed_team.py --backend ollama --model qwen3-coder:30b \
        --goal "Implement reverse_words(s): reverse word order, collapse runs of spaces."

Run (local MLX North Mini Code):
    DEPONENT_MLX_MODEL=mlx-community/North-Mini-Code-1.0-4bit \
        python3 examples/governed_team.py --backend mlx --goal "..."
"""
from __future__ import annotations
import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run without install

from deponent import Cell
from deponent.jail import jail_available
from backends import make_backend

WORK = Path(os.environ.get("DEPONENT_EXAMPLE_WORKDIR", str(Path(tempfile.gettempdir()) / "deponent-team")))

TOOLS = [
    {"type": "function", "function": {"name": "write_file",
        "description": "Write text to a file (relative path inside the work dir). Overwrites.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "read_file",
        "description": "Read a file from the work dir.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "run_cmd",
        "description": "Run a shell command in the work dir, e.g. 'python -m pytest -q'.",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
]


def architect(goal: str, module_stem: str, backend) -> str:
    base = ("You are the ARCHITECT. Write a single pytest file named test_acceptance.py "
            f"that pins down 'done' for this goal (4-8 deterministic asserts, `import {module_stem}` "
            "as the module under test, cover the edge cases named in the goal).\n\nGOAL: " + goal)
    # The test must be VALID Python or it poisons the whole run — validate with
    # ast.parse and retry with a harder forcing instruction if it isn't.
    attempts = [(3000, " Return ONLY the file content in one ```python fence."),
                (4000, " Output ONLY valid Python inside one ```python fence — NO prose, no commentary.")]
    src = ""
    for mt, instr in attempts:
        body = backend.chat([backend.user(base + instr)], tools=None, max_tokens=mt)["final"] or ""
        m = (re.search(r"```python\s*\n(.*?)```", body, re.DOTALL)
             or re.search(r"```python\s*\n(.*)", body, re.DOTALL))
        src = re.sub(r"<\|[^|>]*\|>", "", (m.group(1) if m else body)).strip()
        try:
            ast.parse(src)
            if "def test" in src:
                return src
        except SyntaxError:
            continue
    return src  # last attempt (may be invalid — verification will surface it honestly)


def builder_loop(cell: Cell, goal: str, module: str, backend, max_steps=12):
    messages = [backend.user(goal)]
    for step in range(1, max_steps + 1):
        turn = backend.chat(messages, tools=TOOLS, max_tokens=3500)
        if not turn["tool_calls"]:
            # Self-reported "done" is not evidence — verify the work exists and the
            # tests are actually green before accepting it; otherwise push back.
            mod_exists = (WORK / module).exists()
            chk = cell.act("run_cmd", {"cmd": "python -m pytest -q test_acceptance.py"}, agent="builder") if mod_exists else None
            if chk and "exit=0" in chk.output:
                print(f"  [step {step}] FINAL (verified green): {(turn['final'] or '')[:110]}", flush=True)
                return turn["final"] or ""
            why = (f"{module} has not been created yet" if not mod_exists
                   else f"pytest is NOT green:\n{chk.output[-400:]}")
            print(f"  [step {step}] REJECTED premature 'done' — {why.splitlines()[0][:80]}", flush=True)
            messages.append(backend.user(
                f"You stopped, but the task is NOT complete: {why}. Do the work now — use write_file "
                f"to create/fix {module}, then run_cmd `python -m pytest -q test_acceptance.py`. "
                "Do not stop until pytest reports every test passed."))
            continue
        backend.append_assistant(messages, turn)
        for c in turn["tool_calls"]:
            r = cell.act(c["name"], c["args"], agent="builder")        # gate + jail + ledger
            mark = "OK" if r.allowed else "BLOCK"
            argstr = ", ".join(c["args"]) if isinstance(c["args"], dict) else str(c["args"])[:40]
            print(f"  [step {step}] [{mark}] {c['name']}({argstr}) "
                  f"[{r.decision.blast_class}] -> {r.output.replace(chr(10),' ')[:90]}", flush=True)
            backend.append_tool_result(messages, c["id"], r.output[:3500])
    return "MAX_STEPS_REACHED"


def _extract_verdict(body: str):
    cands = re.findall(r"\{[^{}]*\"verdict\"[^{}]*\}", body, re.DOTALL)
    if not cands:
        m = re.search(r"\{.*\}", body, re.DOTALL)
        cands = [m.group(0)] if m else []
    for raw in reversed(cands):
        try:
            v = json.loads(raw)
            if str(v.get("verdict", "")).upper() in ("CLEAN", "BLOCKED"):
                return v
        except Exception:
            continue
    return None


def reviewer(goal, code, test_src, pytest_out, backend) -> dict:
    base = ("You are the REVIEWER (independent, ADVISORY). Flag if the work does NOT genuinely "
            "meet the GOAL — not just that tests pass, but that the test is adequate and the code "
            "correct.\n\n"
            f"GOAL:\n{goal}\n\nIMPLEMENTATION:\n{code}\n\nACCEPTANCE TEST:\n{test_src}\n\nPYTEST:\n{pytest_out}"
            '\n\nThink BRIEFLY, then output ONLY this JSON: {"verdict":"CLEAN"|"BLOCKED","reasons":["..."]}')
    body = backend.chat([backend.user(base)], tools=None, max_tokens=2500)["final"] or ""
    v = _extract_verdict(body)
    return v if v is not None else {"verdict": "ADVISORY_NA", "reasons": [body[:150]]}


def main():
    ap = argparse.ArgumentParser(description="A governed agent team built on Deponent (model-agnostic).")
    ap.add_argument("--goal", required=True, help="goal text, or @path to read the goal from a file")
    ap.add_argument("--module", default="solution.py", help="module filename the Builder creates")
    ap.add_argument("--steps", type=int, default=12, help="max Builder tool-loop steps")
    ap.add_argument("--backend", default="ollama", choices=["mlx", "ollama"], help="agent backend")
    ap.add_argument("--model", default=None, help="model id/path (env DEPONENT_MLX_MODEL for the mlx default)")
    args = ap.parse_args()

    goal = args.goal
    if goal.startswith("@"):
        goal = Path(goal[1:]).expanduser().read_text().strip()
    module = args.module
    module_stem = module[:-3] if module.endswith(".py") else module
    session_id = uuid.uuid4().hex[:12]

    model_ref = args.model or (os.environ.get("DEPONENT_MLX_MODEL") if args.backend == "mlx" else None)
    if model_ref is None:
        ap.error("--model is required (or set DEPONENT_MLX_MODEL for the mlx backend)")

    print(f"loading backend {args.backend}: {model_ref} ...", flush=True)
    _t0 = time.monotonic()
    backend = make_backend(args.backend, model_ref)
    print(f"backend ready ({backend.name}) in {time.monotonic()-_t0:.1f}s\n", flush=True)

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    # On macOS the jail engages automatically; elsewhere the gate still governs and
    # run_cmd refuses to execute un-jailed (fail-closed). Set use_jail=False to opt
    # into gate-only on a platform where you provide your own sandbox.
    cell = Cell(WORK, ledger_path=WORK / "ledger.jsonl", use_jail=jail_available())

    print("=" * 64 + f"\n[1] ARCHITECT — acceptance test (module {module})\n" + "=" * 64, flush=True)
    test_src = architect(goal, module_stem, backend)
    (WORK / "test_acceptance.py").write_text(test_src)
    print(test_src[:900], flush=True)

    print("\n" + "=" * 64 + "\n[2] BUILDER — gated tool loop (every action gated + chained)\n" + "=" * 64, flush=True)
    build_goal = (goal + f"\n\nAn acceptance test EXISTS at test_acceptance.py — do NOT modify it. "
                  f"Workflow: (1) read_file test_acceptance.py, (2) write_file {module} with the "
                  f"implementation, (3) run_cmd `python -m pytest -q test_acceptance.py`, (4) if it "
                  f"fails, fix {module} and re-run. Use ONLY write_file/read_file/run_cmd and the "
                  "pytest command. When green, summarize.")
    builder_loop(cell, build_goal, module, backend, max_steps=args.steps)

    print("\n" + "=" * 64 + "\n[3] ADVERSARIAL PROBE — rogue action hits the gate live\n" + "=" * 64, flush=True)
    r = cell.act("run_cmd", {"cmd": "rm -rf ~/Documents"}, agent="builder")
    print(f"  injected: run_cmd 'rm -rf ~/Documents' -> {r.decision.verdict} [{r.decision.blast_class}]", flush=True)

    print("\n" + "=" * 64 + "\n[4] INDEPENDENT VERIFICATION (out-of-band, not self-report)\n" + "=" * 64, flush=True)
    vr = subprocess.run("python -m pytest -q test_acceptance.py", shell=True, cwd=WORK,
                        capture_output=True, text=True)
    pytest_out = (vr.stdout + vr.stderr)[-600:]
    print(pytest_out, flush=True)
    test_pass = vr.returncode == 0

    print("=" * 64 + "\n[5] REVIEWER — independent verdict (advisory)\n" + "=" * 64, flush=True)
    code = (WORK / module).read_text() if (WORK / module).exists() else "(no module)"
    verdict = reviewer(goal, code, test_src, pytest_out, backend)
    print(json.dumps(verdict, indent=2), flush=True)

    print("\n" + "=" * 64 + "\n[6] TESTIMONY — hash chain integrity\n" + "=" * 64, flush=True)
    ok, msg = cell.verify()
    allowed = sum(1 for e in cell.ledger.entries if e["verdict"] == "ALLOW")
    blocked = sum(1 for e in cell.ledger.entries if e["verdict"] == "BLOCK")
    print(f"  chain: {msg}  |  ALLOW={allowed} BLOCK={blocked}", flush=True)

    print("\n" + "=" * 64 + "\nGOVERNED TEAM RESULT\n" + "=" * 64, flush=True)
    rv = verdict.get("verdict")
    # Certification anchors on DETERMINISTIC signals (out-of-band test green + chain
    # intact + rogue blocked). The LLM Reviewer is ADVISORY — recorded, not gating.
    overall = test_pass and ok and blocked >= 1
    advisory_flag = "" if rv == "CLEAN" else f"  [reviewer flagged: {rv}]"
    print(f"  test_pass={test_pass}  chain_intact={ok}  gate_blocked_rogue={blocked>=1}  reviewer(advisory)={rv}", flush=True)
    print(f"  => {'GOVERNED PASS — built, gated, testified' + advisory_flag if overall else 'INCOMPLETE'}", flush=True)

    print("\n" + "=" * 64 + "\n[7] RECEIPT -> store\n" + "=" * 64, flush=True)
    try:
        from deponent import persist, write_operator_receipt
        receipt = persist(cell.ledger, session_id=session_id, model=backend.name,
                          task=f"{module}: {goal[:100]}", runtime=args.backend,
                          outcome="GOVERNED_PASS" if overall else "INCOMPLETE")
        write_operator_receipt(receipt)
        print(f"  receipt_id={receipt['receipt_id']}  verified=YES", flush=True)
    except Exception as e:
        # Fail-closed: a receipt that can't be emitted/verified is reported, not hidden.
        print(f"  RECEIPT EMIT FAILED (fail-closed): {type(e).__name__}: {e}", flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
