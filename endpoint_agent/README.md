# OpenIntelligence endpoint agent

One Python client supports Windows, Linux, and macOS. It generates a 3072-bit RSA key and CSR locally, exchanges a **single-use** enrollment key for an mTLS certificate, and then sends heartbeats and software inventory. The private key never leaves the endpoint.

## Run

```bash
python -m pip install cryptography
cp endpoint_agent/config.example.json endpoint_agent/config.json
export OPENINTEL_ENROLLMENT_KEY='single-use-key-shown-by-the-platform'
python -m endpoint_agent.client --config endpoint_agent/config.json --once
```

Remove `--once` to run continuously. Install the same command as a Windows Service, systemd unit, or macOS LaunchDaemon for persistent operation.

## Deliberate limits

- No shell execution, arbitrary script execution, or inbound listener exists.
- The first slice reports inventory and liveness only. Endpoint intents remain approval-only until the server publishes a nonce-protected agent polling route.
- A heartbeat proves last contact, not current health.
- Inventory without a CPE cannot be matched to CVEs; exposure counts remain a floor.
- Enrollment requires the CA configured by the backend and a one-time API key with `enroll` scope.
