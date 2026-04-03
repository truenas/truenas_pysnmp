# truenas_pysnmp

Python C extension for SNMP functionality using net-snmp's libnetsnmp.

Currently provides SNMP trap sending (`send_alert`, `send_alert_cancellation`, `get_engine_id`). Supports SNMPv2c and SNMPv3 (USM auth/priv). Notification OIDs (`alert`, `alertCancellation`, `alertId`, `alertLevel`, `alertMessage`) are derived from the notification section of [TRUENAS-MIB](https://github.com/truenas/middleware/blob/master/src/freenas/usr/local/share/snmp/mibs/TRUENAS-MIB.txt) and compiled as constants, so no runtime MIB parsing is required.

## Building

```bash
sudo apt install libsnmp-dev python3-dev
pip install -e .
```
