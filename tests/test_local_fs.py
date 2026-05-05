# Made by Sn0w8ird

import pytest

from cpointed.local.wp_enumerator import enumerate_wordpress_installs
from cpointed.persistence.wordpress import MuPluginPersistence


def test_enumerate_wordpress_finds_install(tmp_path):
    site = tmp_path / "site"
    (site / "wp-includes").mkdir(parents=True)
    (site / "wp-includes" / "version.php").write_text("x", encoding="utf-8")
    (site / "wp-config.php").write_text("x", encoding="utf-8")

    found = enumerate_wordpress_installs(tmp_path, max_depth=6, max_installs=50)
    assert len(found) == 1
    assert found[0].root == site.resolve()


def test_mu_plugin_probe_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("CPOINTED_AUTHORIZED", "1")
    (tmp_path / "wp-includes").mkdir(parents=True)
    (tmp_path / "wp-includes" / "version.php").write_text("x", encoding="utf-8")
    (tmp_path / "wp-config.php").write_text("x", encoding="utf-8")

    out = MuPluginPersistence(tmp_path).deploy_sync()
    assert out.is_file()
    txt = out.read_text(encoding="utf-8")
    assert "Lab Probe" in txt


def test_mu_plugin_blocked_without_authorization(tmp_path, monkeypatch):
    monkeypatch.delenv("CPOINTED_AUTHORIZED", raising=False)
    (tmp_path / "wp-includes").mkdir(parents=True)
    (tmp_path / "wp-includes" / "version.php").write_text("x", encoding="utf-8")
    (tmp_path / "wp-config.php").write_text("x", encoding="utf-8")

    from cpointed.core.exceptions import UnauthorizedOperationError

    with pytest.raises(UnauthorizedOperationError):
        MuPluginPersistence(tmp_path).deploy_sync()
