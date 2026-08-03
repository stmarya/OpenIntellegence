"""Minimal cross-platform OpenIntelligence endpoint agent.

The agent has no remote-shell facility. It enrolls once with a single-use key,
stores an mTLS identity with owner-only permissions, and sends heartbeat plus
software inventory. Windows, Linux, and macOS use the same Python entry point.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import ssl
import stat
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AGENT_VERSION = "0.1.0"


@dataclass(frozen=True)
class AgentConfig:
    api_base_url: str
    state_dir: str
    enrollment_key: str | None = None
    heartbeat_seconds: int = 60
    inventory_every: int = 60
    request_timeout: int = 30

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        key = os.environ.get("OPENINTEL_ENROLLMENT_KEY") or raw.get("enrollment_key")
        return cls(
            api_base_url=str(raw["api_base_url"]).rstrip("/"),
            state_dir=str(raw.get("state_dir", "./agent-state")),
            enrollment_key=key,
            heartbeat_seconds=max(15, int(raw.get("heartbeat_seconds", 60))),
            inventory_every=max(1, int(raw.get("inventory_every", 60))),
            request_timeout=max(5, int(raw.get("request_timeout", 30))),
        )


class AgentClient:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.state = Path(config.state_dir).expanduser().resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.key_path = self.state / "agent.key"
        self.cert_path = self.state / "agent.crt"
        self.ca_path = self.state / "ca.crt"
        self.identity_path = self.state / "identity.json"

    def _write_secret(self, path: Path, value: str) -> None:
        path.write_text(value, encoding="utf-8")
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _request(self, method: str, path: str, payload: dict[str, Any], *, enroll=False) -> dict:
        headers = {"Content-Type": "application/json", "User-Agent": f"openintel-agent/{AGENT_VERSION}"}
        context = ssl.create_default_context()
        if enroll:
            if not self.config.enrollment_key:
                raise RuntimeError("OPENINTEL_ENROLLMENT_KEY is required for first enrollment")
            headers["X-API-Key"] = self.config.enrollment_key
        else:
            context.load_verify_locations(cafile=str(self.ca_path))
            context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
        req = Request(
            f"{self.config.api_base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method=method,
        )
        try:
            with urlopen(req, timeout=self.config.request_timeout, context=context) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read(2048).decode("utf-8", errors="replace")
            raise RuntimeError(f"API returned HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise RuntimeError(f"API unreachable: {exc.reason}") from exc

    def enroll(self) -> dict:
        if self.identity_path.exists():
            return json.loads(self.identity_path.read_text(encoding="utf-8"))
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, hashes.SHA256())
        )
        key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        payload = {
            "hostname": socket.gethostname(),
            "os_family": platform.system().lower(),
            "os_version": platform.platform(),
            "agent_version": AGENT_VERSION,
            "mac_address": None,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        }
        result = self._request("POST", "/agents/enroll", payload, enroll=True)
        self._write_secret(self.key_path, key_pem)
        self._write_secret(self.cert_path, result["certificate_pem"])
        self.ca_path.write_text(result["ca_chain_pem"], encoding="utf-8")
        identity = {
            "agent_id": result["agent_id"],
            "asset_id": result["asset_id"],
            "certificate_expires_at": result["certificate_expires_at"],
        }
        self.identity_path.write_text(json.dumps(identity, indent=2), encoding="utf-8")
        return identity

    @staticmethod
    def _run(command: list[str]) -> list[str]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
            return result.stdout.splitlines() if result.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired):
            return []

    def software_inventory(self) -> list[dict[str, str | None]]:
        system = platform.system().lower()
        items: list[dict[str, str | None]] = []
        if system == "linux":
            lines = self._run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
            if not lines:
                lines = self._run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        elif system == "darwin":
            lines = self._run(["system_profiler", "SPApplicationsDataType", "-json"])
            if lines:
                try:
                    data = json.loads("\n".join(lines)).get("SPApplicationsDataType", [])
                    return [{"name": x.get("_name", "unknown"), "version": x.get("version"), "vendor": None, "cpe_uri": None} for x in data]
                except json.JSONDecodeError:
                    lines = []
        else:
            script = "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object DisplayName | ForEach-Object { $_.DisplayName + \"`t\" + $_.DisplayVersion }"
            lines = self._run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        for line in lines:
            name, _, version = line.partition("\t")
            if name.strip():
                items.append({"name": name.strip(), "version": version.strip() or None, "vendor": None, "cpe_uri": None})
        return items[:10000]

    def heartbeat(self, include_inventory: bool) -> dict:
        payload: dict[str, Any] = {
            "agent_version": AGENT_VERSION,
            "os_version": platform.platform(),
            "ip_address": None,
            "software": self.software_inventory() if include_inventory else None,
        }
        return self._request("POST", "/agents/heartbeat", payload)

    def run_forever(self) -> None:
        self.enroll()
        count = 0
        while True:
            try:
                response = self.heartbeat(include_inventory=count % self.config.inventory_every == 0)
                delay = max(15, int(response.get("next_heartbeat_seconds", self.config.heartbeat_seconds)))
                count += 1
            except RuntimeError as exc:
                print(f"heartbeat failed: {exc}", flush=True)
                delay = min(300, self.config.heartbeat_seconds * 2)
            time.sleep(delay)


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenIntelligence endpoint agent")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", help="enroll and send one heartbeat")
    args = parser.parse_args()
    client = AgentClient(AgentConfig.load(args.config))
    client.enroll()
    if args.once:
        print(json.dumps(client.heartbeat(include_inventory=True), indent=2, default=str))
    else:
        client.run_forever()


if __name__ == "__main__":
    main()
