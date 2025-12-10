from services.cve_engine import CVEEngine


def test_engine_loads():
    engine = CVEEngine()
    # placeholder: no data yet
    assert engine.cves == []
