from enum import StrEnum


class V3AuthProtocol(StrEnum):
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "128SHA224"
    SHA256 = "192SHA256"
    SHA384 = "256SHA384"
    SHA512 = "384SHA512"


class V3PrivProtocol(StrEnum):
    DES = "DES"
    TRIPLE_DES = "3DESEDE"
    AESCFB128 = "AESCFB128"
    AESCFB192 = "AESCFB192"
    AESCFB256 = "AESCFB256"
    AESBLUMENTHALCFB192 = "AESBLUMENTHALCFB192"
    AESBLUMENTHALCFB256 = "AESBLUMENTHALCFB256"


# Must stay in sync with alert_level_from_string() in src/cext/truenas_pysnmp.c
class AlertLevel(StrEnum):
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    ALERT = "alert"
    EMERGENCY = "emergency"
