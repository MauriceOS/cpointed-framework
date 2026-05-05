# Made by Sn0w8ird

from cpointed.scanner.cidr import hosts_from_cidr


def test_cidr_single_host_v4():
    assert hosts_from_cidr("192.0.2.1/32") == ["192.0.2.1"]


def test_cidr_slash30():
    h = hosts_from_cidr("10.0.0.0/30", limit=10)
    assert "10.0.0.1" in h
