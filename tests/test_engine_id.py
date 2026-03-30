"""Tests for engine ID functionality."""

import truenas_pysnmp


def test_engine_id_returns_bytes():
    eid = truenas_pysnmp.get_engine_id()
    assert isinstance(eid, bytes)


def test_engine_id_not_empty():
    eid = truenas_pysnmp.get_engine_id()
    assert len(eid) > 0


def test_engine_id_stable():
    eid1 = truenas_pysnmp.get_engine_id()
    eid2 = truenas_pysnmp.get_engine_id()
    assert eid1 == eid2
