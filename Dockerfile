# Deponent — a governed sovereign agent kernel. "It doesn't answer. It testifies."
# Zero third-party deps in the core, so this image is tiny and offline-buildable.
#
#   docker build -t deponent .
#   docker run --rm deponent                 # scores the kernel against its own standard
#   docker run --rm deponent make test       # run the suite in-container
#
# NOTE on confinement in-container: the in-language jail is macOS Seatbelt (host) or a
# Docker backend (host daemon). Inside this container the gate + ledger + receipts +
# conformance run fully (platform-independent); the live OS-jail escape-proofs are a
# host concern and skip here — by design, not omission.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Deponent"
LABEL org.opencontainers.image.description="A governed sovereign agent kernel — make any local AI agent testify. Deny-by-default gate, tamper-evident hash-chained ledger, verifiable receipts."
LABEL org.opencontainers.image.source="https://github.com/cjchanh/deponent"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY . /app
# stdlib-only core -> the install pulls nothing from the network for the kernel itself.
RUN pip install --no-cache-dir . && python -c "import deponent; print('deponent import OK')"

# Default: score the reference kernel against the GAK conformance standard — the
# 10-second "it actually works" proof. Override with any command (e.g. `make test`).
CMD ["python", "-m", "deponent.conform", "--kernel", "deponent"]
