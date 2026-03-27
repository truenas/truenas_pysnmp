"""Tests for argument validation — no network required."""

import pytest
import truenas_pysnmp


class TestSendAlertValidation:

    def test_missing_host(self):
        with pytest.raises(TypeError, match="host is required"):
            truenas_pysnmp.send_alert(port=162, community="public",
                                       alert_id="x", level="info", message="x")

    def test_port_too_low(self):
        with pytest.raises(ValueError, match="port must be in range"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=0, community="public",
                                       alert_id="x", level="info", message="x")

    def test_port_too_high(self):
        with pytest.raises(ValueError, match="port must be in range"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=99999, community="public",
                                       alert_id="x", level="info", message="x")

    def test_missing_alert_id(self):
        with pytest.raises(TypeError, match="alert_id is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162, community="public",
                                       level="info", message="x")

    def test_missing_level(self):
        with pytest.raises(TypeError, match="level is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162, community="public",
                                       alert_id="x", message="x")

    def test_missing_message(self):
        with pytest.raises(TypeError, match="message is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162, community="public",
                                       alert_id="x", level="info")

    def test_invalid_level(self):
        with pytest.raises(ValueError, match="Invalid alert level"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162, community="public",
                                       alert_id="x", level="bogus", message="x")

    def test_missing_community_v2c(self):
        with pytest.raises(ValueError, match="community is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162,
                                       alert_id="x", level="info", message="x")

    def test_empty_community_v2c(self):
        with pytest.raises(ValueError, match="community is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162, community="",
                                       alert_id="x", level="info", message="x")

    def test_missing_v3_username(self):
        with pytest.raises(ValueError, match="v3_username is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162,
                                       v3=True, alert_id="x", level="info", message="x")

    def test_auth_protocol_without_key(self):
        with pytest.raises(ValueError, match="v3_authkey is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162,
                                       v3=True, v3_username="user",
                                       v3_authprotocol="SHA",
                                       alert_id="x", level="info", message="x")

    def test_priv_protocol_without_key(self):
        with pytest.raises(ValueError, match="v3_privkey is required"):
            truenas_pysnmp.send_alert(host="127.0.0.1", port=162,
                                       v3=True, v3_username="user",
                                       v3_authprotocol="SHA", v3_authkey="pass",
                                       v3_privprotocol="AESCFB128",
                                       alert_id="x", level="info", message="x")

    def test_wrong_type_host(self):
        with pytest.raises(TypeError):
            truenas_pysnmp.send_alert(host=12345, port=162, community="public",
                                       alert_id="x", level="info", message="x")

    def test_wrong_type_port(self):
        with pytest.raises(TypeError):
            truenas_pysnmp.send_alert(host="127.0.0.1", port="abc", community="public",
                                       alert_id="x", level="info", message="x")

    def test_no_args(self):
        with pytest.raises(TypeError):
            truenas_pysnmp.send_alert()


class TestSendAlertCancellationValidation:

    def test_missing_alert_id(self):
        with pytest.raises(TypeError, match="alert_id is required"):
            truenas_pysnmp.send_alert_cancellation(host="127.0.0.1", port=162,
                                                    community="public")

    def test_missing_community_v2c(self):
        with pytest.raises(ValueError, match="community is required"):
            truenas_pysnmp.send_alert_cancellation(host="127.0.0.1", port=162,
                                                    alert_id="x")

    def test_missing_host(self):
        with pytest.raises(TypeError, match="host is required"):
            truenas_pysnmp.send_alert_cancellation(port=162, community="public",
                                                    alert_id="x")
