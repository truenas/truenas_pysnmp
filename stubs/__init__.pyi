"""Type stubs for truenas_pysnmp module.

This module provides SNMP functionality for TrueNAS using the net-snmp
library (libnetsnmp). Currently supports sending SNMPv2c and SNMPv3 traps.
"""

from truenas_pysnmp.constants import AlertLevel as AlertLevel
from truenas_pysnmp.constants import V3AuthProtocol as V3AuthProtocol
from truenas_pysnmp.constants import V3PrivProtocol as V3PrivProtocol


class SNMPError(RuntimeError):
    """Exception raised when an SNMP operation fails."""
    ...


def send_alert(
    *,
    host: str,
    port: int,
    community: str | None = None,
    v3: bool = False,
    v3_username: str | None = None,
    v3_authprotocol: V3AuthProtocol | str | None = None,
    v3_authkey: str | None = None,
    v3_privprotocol: V3PrivProtocol | str | None = None,
    v3_privkey: str | None = None,
    engine_id: bytes | None = None,
    alert_id: str,
    level: AlertLevel | str,
    message: str,
) -> None:
    """Send a TrueNAS alert SNMP trap notification.

    Sends an SNMPv2 TRAP PDU with the TRUENAS-MIB::alert notification type,
    carrying alertId, alertLevel, and alertMessage varbinds.

    Parameters
    ----------
    host : str
        Trap receiver hostname or IP address.
    port : int
        Trap receiver UDP port (1-65535).
    community : str, optional
        SNMPv2c community string. Required when v3 is False.
    v3 : bool, optional
        Use SNMPv3 instead of SNMPv2c (default False).
    v3_username : str, optional
        SNMPv3 USM security name. Required when v3 is True.
    v3_authprotocol : V3AuthProtocol or str, optional
        SNMPv3 authentication protocol.
    v3_authkey : str, optional
        SNMPv3 authentication passphrase.
    v3_privprotocol : V3PrivProtocol or str, optional
        SNMPv3 privacy protocol.
    v3_privkey : str, optional
        SNMPv3 privacy passphrase.
    engine_id : bytes, optional
        Explicit SNMPv3 engine ID. If None, uses the engine ID
        generated at module import (see get_engine_id()).
    alert_id : str
        Unique alert identifier (UUID).
    level : AlertLevel or str
        Alert severity level.
    message : str
        Human-readable alert message.

    Raises
    ------
    SNMPError
        If sending the trap fails.
    ValueError
        If an invalid alert level or port is provided.
    TypeError
        If required arguments are missing.
    """
    ...


def send_alert_cancellation(
    *,
    host: str,
    port: int,
    community: str | None = None,
    v3: bool = False,
    v3_username: str | None = None,
    v3_authprotocol: V3AuthProtocol | str | None = None,
    v3_authkey: str | None = None,
    v3_privprotocol: V3PrivProtocol | str | None = None,
    v3_privkey: str | None = None,
    engine_id: bytes | None = None,
    alert_id: str,
) -> None:
    """Send a TrueNAS alert cancellation SNMP trap notification.

    Sends an SNMPv2 TRAP PDU with the TRUENAS-MIB::alertCancellation
    notification type, carrying only the alertId varbind.

    Parameters
    ----------
    host : str
        Trap receiver hostname or IP address.
    port : int
        Trap receiver UDP port (1-65535).
    community : str, optional
        SNMPv2c community string. Required when v3 is False.
    v3 : bool, optional
        Use SNMPv3 instead of SNMPv2c (default False).
    v3_username : str, optional
        SNMPv3 USM security name. Required when v3 is True.
    v3_authprotocol : V3AuthProtocol or str, optional
        SNMPv3 authentication protocol.
    v3_authkey : str, optional
        SNMPv3 authentication passphrase.
    v3_privprotocol : V3PrivProtocol or str, optional
        SNMPv3 privacy protocol.
    v3_privkey : str, optional
        SNMPv3 privacy passphrase.
    engine_id : bytes, optional
        Explicit SNMPv3 engine ID. If None, uses the engine ID
        generated at module import (see get_engine_id()).
    alert_id : str
        Unique alert identifier (UUID) of the alert being cancelled.

    Raises
    ------
    SNMPError
        If sending the trap fails.
    ValueError
        If an invalid port is provided.
    TypeError
        If required arguments are missing.
    """
    ...


def get_engine_id() -> bytes:
    """Return the SNMPv3 engine ID used by this module.

    The engine ID is generated once at module import and remains stable
    for the lifetime of the process.

    Returns
    -------
    bytes
        The engine ID as raw bytes.

    Raises
    ------
    SNMPError
        If the engine ID was not initialized.
    """
    ...
