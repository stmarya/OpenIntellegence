"""Generate a development certificate authority for endpoint agents.

Usage::

    python -m app.agent_gateway.bootstrap_ca --out ./certs

This exists so a developer can bring the agent gateway up locally without
an HSM. It is explicitly not a production tool: the CA private key is
written unencrypted to disk, and anyone holding it can mint a certificate
for any agent in any tenant. In production the CA key belongs in a KMS or
HSM and this script should never be run.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

from app.agent_gateway.mtls import AgentCertificateAuthority


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="./certs", help="output directory")
    parser.add_argument(
        "--common-name", default="OpenIntelligence Agent CA", help="CA common name"
    )
    parser.add_argument("--days", type=int, default=3650, help="CA validity in days")
    parser.add_argument(
        "--force", action="store_true", help="overwrite an existing CA"
    )
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / "agent-ca.crt"
    key_path = out / "agent-ca.key"

    if (cert_path.exists() or key_path.exists()) and not args.force:
        # Silently overwriting a CA would orphan every already-enrolled
        # agent, because their certificates would no longer chain to it.
        print(
            f"Refusing to overwrite an existing CA in {out}.\n"
            "Every enrolled agent would stop authenticating. "
            "Pass --force if that is genuinely what you want.",
            file=sys.stderr,
        )
        return 1

    _, cert_pem, key_pem = AgentCertificateAuthority.create_self_signed(
        common_name=args.common_name, valid_days=args.days
    )

    cert_path.write_text(cert_pem)
    key_path.write_text(key_pem)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    print(f"CA certificate: {cert_path}")
    print(f"CA private key: {key_path} (mode 0600)")
    print(
        "\nSet these in your .env:\n"
        f"  AGENT_CA_CERT_PATH={cert_path}\n"
        f"  AGENT_CA_KEY_PATH={key_path}\n"
        "\nDevelopment use only. Do not deploy this key to production."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
