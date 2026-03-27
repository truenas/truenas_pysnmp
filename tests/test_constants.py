"""Tests for constants and their consistency with C module."""

from enum import StrEnum

from truenas_pysnmp.constants import AlertLevel, V3AuthProtocol, V3PrivProtocol
import truenas_pysnmp


def test_alert_level_is_strenum():
    assert issubclass(AlertLevel, StrEnum)


def test_v3_auth_protocol_is_strenum():
    assert issubclass(V3AuthProtocol, StrEnum)


def test_v3_priv_protocol_is_strenum():
    assert issubclass(V3PrivProtocol, StrEnum)


def test_alert_levels_accepted_by_c_module():
    """Every AlertLevel constant must be accepted by the C module."""
    for level in AlertLevel:
        # Should not raise — validation only, no network needed
        # We expect ValueError for missing community, not for level
        try:
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162,
                                       community="public",
                                       alert_id="test", level=level,
                                       message="test")
        except truenas_pysnmp.SNMPError:
            # Network error is fine — means validation passed
            pass


def test_constants_work_as_strings():
    assert str(V3AuthProtocol.SHA) == "SHA"
    assert str(V3AuthProtocol.MD5) == "MD5"
    assert str(V3PrivProtocol.DES) == "DES"
    assert str(V3PrivProtocol.AESCFB128) == "AESCFB128"
    assert str(AlertLevel.CRITICAL) == "critical"
    assert str(AlertLevel.INFO) == "info"


def test_snmp_error_is_runtime_error():
    assert issubclass(truenas_pysnmp.SNMPError, RuntimeError)
