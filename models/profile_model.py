from pydantic import BaseModel
from typing import Optional


class SNMPProfile(BaseModel):
    host: Optional[str] = None
    user: Optional[str] = None
    group: Optional[str] = None
    auth_password: Optional[str] = None
    priv_password: Optional[str] = None


class NTPProfile(BaseModel):
    primary_server: Optional[str] = None
    secondary_server: Optional[str] = None
    timezone: Optional[str] = None


class AAAProfile(BaseModel):
    enable_secret: Optional[str] = None
    tacacs1_name: Optional[str] = None
    tacacs1_ip: Optional[str] = None
    tacacs1_key: Optional[str] = None
    tacacs2_name: Optional[str] = None
    tacacs2_ip: Optional[str] = None
    tacacs2_key: Optional[str] = None


class DeviceProfile(BaseModel):
    """Full multi-generator device profile"""
    name: str
    snmp: SNMPProfile = SNMPProfile()
    ntp: NTPProfile = NTPProfile()
    aaa: AAAProfile = AAAProfile()
