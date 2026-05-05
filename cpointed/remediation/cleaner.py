# Made by Sn0w8ird
#!/usr/bin/env python3
"""cPanel-oriented incident cleanup over SSH (blue team)."""

from __future__ import annotations

import os
import sys


def remediate_cpanel(host: str, username: str, key_path: str, *, auto_patch: bool = False) -> None:
    if os.environ.get("CPOINTED_AUTHORIZED") != "1":
        print("Set CPOINTED_AUTHORIZED=1 for remote remediation.", file=sys.stderr)
        raise SystemExit(2)
    try:
        import paramiko
    except ImportError as exc:
        print("Install paramiko: pip install 'cpointed[remediation]'", file=sys.stderr)
        raise SystemExit(2) from exc

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, key_filename=key_path)

    def run(cmd: str) -> None:
        ssh.exec_command(cmd)

    run("pkill -9 nuclear.x86 2>/dev/null; pkill -9 xmrig 2>/dev/null; pkill -9 minecraftd 2>/dev/null")
    run("find /home -path '*/wp-content/mu-plugins/*' -name '*cpointed*' -delete 2>/dev/null")
    run("crontab -l 2>/dev/null | grep -v 'cpointed' | crontab - 2>/dev/null")
    run("sed -i '/cpointed_backdoor/d' /root/.ssh/authorized_keys 2>/dev/null")
    run("rm -rf /var/cpanel/sessions/raw/* /var/cpanel/sessions/cache/* 2>/dev/null")
    run("systemctl restart cpsrvd 2>/dev/null || /scripts/restartsrv_cpsrvd 2>/dev/null")
    if auto_patch:
        run("/scripts/upcp --force")
    ssh.close()
    print("[+] Remediation commands issued (verify on host).")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 3:
        print("Usage: python -m cpointed.remediation.cleaner <host> <user> <key_path> [--auto-patch]", file=sys.stderr)
        return 2
    auto = "--auto-patch" in argv
    args = [a for a in argv if a != "--auto-patch"]
    remediate_cpanel(args[0], args[1], args[2], auto_patch=auto)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
