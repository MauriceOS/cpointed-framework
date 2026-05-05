# Made by Sn0w8ird

from cpointed.core.engine import CPointedEngine, ScanResult, Target
from cpointed.modules.base import VulnerabilityModule


class DummyMod(VulnerabilityModule):
    name = "dummy"
    severity = 1.0

    def applies_to(self, target: Target) -> bool:
        return True

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return self._result(target, True, 1.0, {"ok": True})


def test_engine_runs_module():
    e = CPointedEngine(threads=2, timeout=5)
    e.register_module(DummyMod())
    import asyncio

    t = Target(host="127.0.0.1", port=9999)
    results = asyncio.run(e.scan_target(t))
    assert len(results) == 1
    assert results[0].vulnerable is True
