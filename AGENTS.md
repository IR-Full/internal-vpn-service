# Project workflow

- Read README.md and docs/verification.md before changing deployment defaults. This repository is not a live VPN deployment.
- The agreed design is two European nodes and a €50 monthly ceiling. No server purchase is authorised by code publication.
- Use local Graphify navigation before code analysis; verify in current source and tests. Refresh `graphify-out/graph.json` with `GRAPHIFY_BACKEND=none graphify extract . --code-only --max-workers 2` after source changes. Keep its output local and ignored.
- Never commit `.state/`, credentials, client exports, QR codes, private keys or decrypted Ansible inventory. Test-only fixtures must remain distinguishable from real deployment values.
- Keep user traffic content, visited websites and DNS queries out of logging. Monitor aggregates and minimal event categories.
- Do not bypass image security gates or label a failed scan as passing. A functional Grafana startup does not resolve vulnerability findings.
- Use standard cryptography and official VPN implementations; do not invent encryption or obfuscation protocols.

## Testing

- Build controller tooling: `docker build -f tools/Dockerfile -t vpn-service-tools:local .`
- Unit/CLI tests: `docker run --rm -v "$PWD:/workspace" -w /workspace vpn-service-tools:local`
- Templates/Ansible: the same container with `python tools/validate_local.py`.
- Kernel integration: see README.md; capabilities apply only to the networkless disposable test container.
- Grafana and log pipeline smoke tests: `python tools/smoke_stack.py` and `python tools/check_log_privacy.py` on the Docker host.
- Native gateway mTLS/rotation: the tooling container with `--network none` and `python tests/telemetry_lab.py`. Native Windows ACL regressions: `python -m unittest discover -s tests -p test_windows_acl.py -v` on Windows with cryptography installed; Linux skips them.
- Grafana uses the official slim image plus exactly two checksum-pinned, signature-verified plugins. Scan the four images and both plugin Go binaries with `python tools/scan_images.py`; use `rootfs` for plugin binaries, not `fs`. Do not preinstall unpinned plugins or disable signatures.
- `docs/acceptance.md` describes real VPS/client tests. Do not replace their evidence with local Docker throughput or configured boolean flags.
- No remote publication, production deployment or notification sending is performed automatically by tests.
