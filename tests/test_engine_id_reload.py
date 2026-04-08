"""Tests for engine ID persistence and auto-reload."""

import os
import subprocess
import sys
import time

import pytest
import truenas_pysnmp

PERSIST_FILE = "/data/subsystems/snmp/truenas_pysnmp.conf"

pytestmark = pytest.mark.skipif(
    not os.path.exists(PERSIST_FILE),
    reason="Persistent file not available"
)


def _write_config(content):
    time.sleep(1)
    with open(PERSIST_FILE, "w") as f:
        f.write(content)


@pytest.fixture(autouse=True)
def _save_restore():
    with open(PERSIST_FILE) as f:
        orig = f.read()
    yield
    _write_config(orig)


def test_stable_across_processes():
    eid = truenas_pysnmp.get_engine_id().hex()
    out = subprocess.check_output([
        sys.executable, "-c",
        "import truenas_pysnmp; print(truenas_pysnmp.get_engine_id().hex())"
    ]).strip().decode()
    assert eid == out


def test_reload_on_change():
    _write_config("engineBoots 1\noldEngineID 0xdeadbeef0102030405060708\n")
    assert truenas_pysnmp.get_engine_id() == b"\xde\xad\xbe\xef\x01\x02\x03\x04\x05\x06\x07\x08"


def test_no_spurious_reload():
    assert truenas_pysnmp.get_engine_id() == truenas_pysnmp.get_engine_id()


def test_restore_original():
    orig = truenas_pysnmp.get_engine_id()
    with open(PERSIST_FILE) as f:
        saved = f.read()

    _write_config("engineBoots 1\noldEngineID 0xdeadbeef0102030405060708\n")
    assert truenas_pysnmp.get_engine_id() != orig

    _write_config(saved)
    assert truenas_pysnmp.get_engine_id() == orig
