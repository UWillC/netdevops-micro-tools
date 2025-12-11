from services.cve_engine import CVEEngine


def test_cve_engine_loads():
    engine = CVEEngine()
    engine.load_all()
    assert len(engine.cves) >= 1


def test_match_logic():
    engine = CVEEngine()
    engine.load_all()
    matched = engine.match("ISR4451-X", "17.5.1")
    assert isinstance(matched, list)
