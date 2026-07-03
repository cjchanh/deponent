.PHONY: help test demo self-gate self-gate-live install lint clean

help:
	@echo "make test      - run the full suite (jail tests are macOS-only)"
	@echo "make demo      - run the minimal testify demo (no model needed)"
	@echo "make self-gate      - dogfood: deponent gates its own development (CONFORMANT + SOUND)"
	@echo "make self-gate-live - full dogfood: govern a REAL jailed git+rustc self-build"
	@echo "make install   - editable install of the kernel"
	@echo "make lint      - ruff check (if installed)"
	@echo "make clean     - remove caches + runtime artifacts"

# Dogfood / quality ratchet: the engine gates the engine. Exit non-zero if the
# reference kernel stops passing its own GAK clauses, or a governed self-build's
# testimony is not sound. Wire as a pre-commit / CI check.
self-gate:
	python3 -m deponent.selfgate

# Full dogfood: deponent governs its OWN real git+rustc build, jailed — the local
# commit ALLOWs and runs, the push BLOCKs at the irreversible floor, all testified.
self-gate-live:
	python3 -m deponent.selfgate --live

test:
	python3 -m pytest -q

demo:
	python3 examples/minimal.py

install:
	python3 -m pip install -e .

lint:
	ruff check . || true

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__ build dist *.egg-info .deponent runs
