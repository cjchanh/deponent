#!/usr/bin/env python3
"""
backends.py — model-agnostic agent backend for the governed team example.

Deponent's gate / jail / ledger / receipt layers never cared which model runs.
The AGENT LOOP did: one model speaks Cohere's text tool-protocol
(<|START_ACTION|>...), another returns native structured tool_calls. This module
hides that behind one interface so the same governed harness drives either —
proof that the governance kernel is independent of the reasoning core.

A Backend exposes:
  chat(messages, tools, max_tokens) -> {thinking, tool_calls:[{id,name,args}], final, raw}
  append_assistant(messages, turn)        # record what the model just did
  append_tool_result(messages, id, text)  # feed a tool's output back
  user(text)                              # a user message in this backend's shape

To add your own model, implement those four methods and register it in
make_backend(). The Cell does not change.
"""
from __future__ import annotations
import json
import re
import urllib.request
import uuid


def make_backend(kind: str, model: str):
    if kind == "mlx":
        return MLXBackend(model)
    if kind == "ollama":
        return OllamaBackend(model)
    raise ValueError(f"unknown backend {kind!r} (use mlx|ollama, or add your own)")


# --------------------------------------------------------------------------- MLX
class MLXBackend:
    """mlx-vlm + Cohere2 native tool protocol (text tokens). macOS / Apple Silicon.

    Reference model: a local 4-bit North Mini Code (Cohere, Apache-2.0). Requires
    `pip install mlx-vlm` and a local model path/id."""

    GEN = dict(temperature=0.3, repetition_penalty=1.05, repetition_context_size=64)

    def __init__(self, model_path: str):
        from mlx_vlm import load, generate
        from mlx_vlm.prompt_utils import apply_chat_template
        self._generate = generate
        self._tmpl = apply_chat_template
        self.model, self.processor = load(model_path)
        self.cfg = getattr(self.model, "config", None)
        self.name = "mlx:" + model_path.rstrip("/").split("/")[-1]

    def user(self, text):
        return {"role": "user", "content": text}

    def chat(self, messages, tools, max_tokens=3000):
        formatted = self._tmpl(self.processor, self.cfg, messages, tools=tools,
                               add_generation_prompt=True, num_images=0)
        raw = self._generate(self.model, self.processor, formatted,
                             verbose=False, max_tokens=max_tokens, **self.GEN).text
        th = re.search(r"<\|START_THINKING\|>(.*?)<\|END_THINKING\|>", raw, re.DOTALL)
        ac = re.search(r"<\|START_ACTION\|>(.*?)<\|END_ACTION\|>", raw, re.DOTALL)
        rp = re.search(r"<\|START_RESPONSE\|>(.*?)(?:<\|END_RESPONSE\|>|$)", raw, re.DOTALL)
        thinking = th.group(1).strip() if th else ""
        calls = []
        if ac:
            try:
                for c in json.loads(ac.group(1).strip()):
                    calls.append({"id": str(c["tool_call_id"]), "name": c["tool_name"], "args": c["parameters"]})
            except Exception:
                calls = []  # malformed action -> treated as no tool call (loop re-prompts)
        final = None
        if not calls:
            final = (rp.group(1).strip() if rp else _strip_tokens(_after_think(raw)))
        return {"thinking": thinking, "tool_calls": calls, "final": final, "raw": raw}

    def append_assistant(self, messages, turn):
        if turn["tool_calls"]:
            messages.append({"role": "assistant", "tool_plan": turn["thinking"],
                "tool_calls": [{"id": c["id"], "type": "function",
                    "function": {"name": c["name"], "arguments": c["args"]}} for c in turn["tool_calls"]]})
        else:
            messages.append({"role": "assistant", "content": turn["final"] or ""})

    def append_tool_result(self, messages, tool_call_id, content):
        messages.append({"role": "tool", "tool_call_id": tool_call_id, "content": content})


# ------------------------------------------------------------------------ Ollama
class OllamaBackend:
    """Ollama /api/chat with native (OpenAI-style) structured tool calls.

    Works with any tool-capable Ollama model (qwen3-coder, etc.). Set OLLAMA_HOST
    to point at a non-default daemon."""

    import os as _os
    HOST = _os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

    def __init__(self, model: str):
        self.model = model
        self.name = "ollama:" + model

    def user(self, text):
        return {"role": "user", "content": text}

    def chat(self, messages, tools, max_tokens=3000):
        body = json.dumps({
            "model": self.model, "messages": messages, "tools": tools, "stream": False,
            "options": {"temperature": 0.3, "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(f"{self.HOST}/api/chat", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode())
        msg = data.get("message", {}) or {}
        thinking = msg.get("thinking", "") or ""
        calls = []
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try: args = json.loads(args)
                except Exception: args = {"_raw": args}
            calls.append({"id": tc.get("id") or uuid.uuid4().hex[:8], "name": fn.get("name", ""), "args": args})
        content = msg.get("content", "") or ""
        final = None if calls else (content or thinking)
        return {"thinking": thinking, "tool_calls": calls, "final": final, "raw": json.dumps(data)[:4000], "_content": content}

    def append_assistant(self, messages, turn):
        m = {"role": "assistant", "content": turn.get("_content", "") or (turn["final"] or "")}
        if turn["tool_calls"]:
            m["tool_calls"] = [{"id": c["id"], "type": "function",
                "function": {"name": c["name"], "arguments": c["args"]}} for c in turn["tool_calls"]]
        messages.append(m)

    def append_tool_result(self, messages, tool_call_id, content):
        messages.append({"role": "tool", "tool_call_id": tool_call_id, "content": content})


def _after_think(text):
    parts = re.split(r"<\|END_THINKING\|>", text)
    return parts[-1] if len(parts) > 1 else text


def _strip_tokens(text):
    return re.sub(r"<\|[^|>]*\|>", "", text).strip()


__all__ = ["make_backend", "MLXBackend", "OllamaBackend"]
