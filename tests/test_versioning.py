# Made by Sn0w8ird

from cpointed.core.versioning import is_strictly_older


def test_version_ordering():
    older, err = is_strictly_older("0.9.123", "0.9.124")
    assert err is None
    assert older is True
    newer, err2 = is_strictly_older("0.9.124", "0.9.124")
    assert newer is False


def test_wpvivid_assessment_flags_old():
    from cpointed.modules.wordpress.cve_2026_1357_wpvivid import CVE20261357WPvivid

    m = CVE20261357WPvivid()
    vuln, meta = m.assess_semver("0.9.123")
    assert vuln is True
    assert meta.get("older_than_fixed") is True
    vuln2, _ = m.assess_semver("0.9.124")
    assert vuln2 is False
