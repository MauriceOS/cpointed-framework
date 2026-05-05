# Made by Sn0w8ird

from __future__ import annotations

import os
from typing import Any, Optional

from cpointed.core.exceptions import UnauthorizedOperationError
from cpointed.core.session import CPointedClient


async def add_ssh_key_whm(
    client: CPointedClient,
    session: str,
    public_key: str,
    *,
    timeout: float = 30.0,
) -> bool:
    """Inject SSH public key into root's authorized_keys via WHM json-api Fileman (authorized testing only)."""
    import urllib.parse

    encoded_key = urllib.parse.quote(public_key, safe="")
    path = (
        "/json-api/cpanel?cpanel_jsonapi_user=root&cpanel_jsonapi_apiversion=2"
        "&cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=savefile"
        f"&path=/root/.ssh/authorized_keys&content={encoded_key}"
    )
    headers = {"Cookie": f"whostmgrsession={session}"}
    resp = await client.request("GET", path, headers=headers, timeout=timeout)
    return resp.status_code == 200


def add_ssh_key_direct(host: str, username: str, password: str, public_key: str) -> bool:
    """Fallback: append key via SSH when credentials are known (requires paramiko)."""
    try:
        import paramiko
    except ImportError:
        return False
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        _, stdout, _ = ssh.exec_command(f'grep -qF "{public_key}" /root/.ssh/authorized_keys 2>/dev/null')
        if stdout.channel.recv_exit_status() != 0:
            quoted = public_key.replace("'", "'\\''")
            ssh.exec_command(f'mkdir -p /root/.ssh && echo "{quoted}" >> /root/.ssh/authorized_keys')
        ssh.close()
        return True
    except Exception:
        return False


def append_authorized_key_via_paramiko(
    *,
    hostname: str,
    port: int,
    username: str,
    public_key_openssh: str,
    pkey_filename: Optional[str] = None,
    password: Optional[str] = None,
) -> None:
    """Append *one* OpenSSH public key line to ``~/.ssh/authorized_keys`` on *hostname*.

    Requires ``paramiko`` (``pip install 'cpointed[remediation]'``) and ``CPOINTED_AUTHORIZED=1``.
    """
    if os.environ.get("CPOINTED_AUTHORIZED") != "1":
        raise UnauthorizedOperationError("Host key operations require CPOINTED_AUTHORIZED=1.")
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - optional dep
        raise RuntimeError("Install paramiko: pip install 'cpointed[remediation]'") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw: dict[str, Any] = {"hostname": hostname, "port": port, "username": username}
    if pkey_filename:
        connect_kw["key_filename"] = pkey_filename
    if password:
        connect_kw["password"] = password
    client.connect(**connect_kw)
    try:
        stdin, stdout, stderr = client.exec_command(
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        )
        stdout.channel.recv_exit_status()
        line = public_key_openssh.strip()
        if not line.startswith("ssh-"):
            raise ValueError("public_key_openssh must be a single ssh-rsa/ed25519 line")
        quoted = line.replace("'", "'\\''")
        cmd = f"grep -qxF '{quoted}' ~/.ssh/authorized_keys || echo '{quoted}' >> ~/.ssh/authorized_keys"
        stdin2, stdout2, stderr2 = client.exec_command(cmd)
        rc = stdout2.channel.recv_exit_status()
        if rc != 0:
            err = stderr2.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"authorized_keys update failed: {err}")
    finally:
        client.close()
