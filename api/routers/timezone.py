"""
Timezone Converter API Router
Convert timestamps between timezones - essential for log correlation.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, available_timezones
import re

router = APIRouter(prefix="/tools/timezone", tags=["Timezone Converter"])

# NATO Military Timezone Letters (phonetic alphabet)
# https://en.wikipedia.org/wiki/List_of_military_time_zones
MILITARY_TIMEZONES = {
    "A": ("Alpha", +1), "B": ("Bravo", +2), "C": ("Charlie", +3),
    "D": ("Delta", +4), "E": ("Echo", +5), "F": ("Foxtrot", +6),
    "G": ("Golf", +7), "H": ("Hotel", +8), "I": ("India", +9),
    "K": ("Kilo", +10), "L": ("Lima", +11), "M": ("Mike", +12),
    "N": ("November", -1), "O": ("Oscar", -2), "P": ("Papa", -3),
    "Q": ("Quebec", -4), "R": ("Romeo", -5), "S": ("Sierra", -6),
    "T": ("Tango", -7), "U": ("Uniform", -8), "V": ("Victor", -9),
    "W": ("Whiskey", -10), "X": ("X-ray", -11), "Y": ("Yankee", -12),
    "Z": ("Zulu", 0),  # UTC
}

# Reverse mapping: offset to letter
OFFSET_TO_MILITARY = {v[1]: k for k, v in MILITARY_TIMEZONES.items()}

# Common network-relevant timezones
COMMON_TIMEZONES = [
    {"id": "UTC", "label": "UTC / ZULU / GMT", "offset_example": "+00:00"},
    {"id": "America/New_York", "label": "EST/EDT (New York)", "offset_example": "-05:00/-04:00"},
    {"id": "America/Chicago", "label": "CST/CDT (Chicago)", "offset_example": "-06:00/-05:00"},
    {"id": "America/Denver", "label": "MST/MDT (Denver)", "offset_example": "-07:00/-06:00"},
    {"id": "America/Los_Angeles", "label": "PST/PDT (Los Angeles)", "offset_example": "-08:00/-07:00"},
    {"id": "Europe/London", "label": "GMT/BST (London)", "offset_example": "+00:00/+01:00"},
    {"id": "Europe/Warsaw", "label": "CET/CEST (Warsaw)", "offset_example": "+01:00/+02:00"},
    {"id": "Europe/Berlin", "label": "CET/CEST (Berlin)", "offset_example": "+01:00/+02:00"},
    {"id": "Asia/Tokyo", "label": "JST (Tokyo)", "offset_example": "+09:00"},
    {"id": "Asia/Singapore", "label": "SGT (Singapore)", "offset_example": "+08:00"},
    {"id": "Asia/Dubai", "label": "GST (Dubai)", "offset_example": "+04:00"},
    {"id": "Australia/Sydney", "label": "AEST/AEDT (Sydney)", "offset_example": "+10:00/+11:00"},
]


class TimezoneConvertRequest(BaseModel):
    """Request to convert a timestamp between timezones."""
    timestamp: str = Field(..., description="Timestamp to convert (ISO format or common formats)")
    from_timezone: str = Field(default="UTC", description="Source timezone (e.g., UTC, America/New_York)")
    to_timezones: List[str] = Field(
        default=["UTC", "America/New_York", "Europe/Warsaw", "Asia/Tokyo"],
        description="Target timezones to convert to"
    )


class TimezoneResult(BaseModel):
    """Single timezone conversion result."""
    timezone: str
    label: str
    datetime_iso: str
    datetime_formatted: str
    offset: str


class TimezoneConvertResponse(BaseModel):
    """Response with converted timestamps."""
    original_input: str
    original_timezone: str
    parsed_utc: str
    results: List[TimezoneResult]


class BatchConvertRequest(BaseModel):
    """Request to convert multiple timestamps."""
    timestamps: List[str] = Field(..., description="List of timestamps to convert")
    from_timezone: str = Field(default="UTC", description="Source timezone")
    to_timezone: str = Field(default="America/New_York", description="Target timezone")


class BatchResult(BaseModel):
    """Single batch conversion result."""
    original: str
    converted: str
    success: bool
    error: Optional[str] = None


class NowResponse(BaseModel):
    """Current time in multiple timezones."""
    generated_at_utc: str
    timezones: List[TimezoneResult]


class DTGResult(BaseModel):
    """NATO Date-Time Group result."""
    timezone: str
    label: str
    military_letter: str
    military_name: str
    dtg_short: str       # 181430Z
    dtg_full: str        # 181430ZFeb26
    dtg_seconds: str     # 18143000ZFeb26
    datetime_iso: str
    datetime_formatted: str


class DTGConvertRequest(BaseModel):
    """Request to convert NATO DTG."""
    dtg: str = Field(..., description="NATO DTG format (e.g., 051100Z, 181430ZFeb26)")


class DTGConvertResponse(BaseModel):
    """Response with parsed NATO DTG."""
    original_input: str
    parsed_utc: str
    dtg_zulu: str
    results: List[DTGResult]


class DTGNowResponse(BaseModel):
    """Current time in NATO DTG format."""
    generated_at_utc: str
    dtg_zulu: str
    dtg_zulu_full: str
    timezones: List[DTGResult]


def parse_dtg(dtg_str: str) -> datetime:
    """
    Parse NATO Date-Time Group format.

    Formats supported:
    - DDHHMMZ (e.g., 051100Z) - day, hour, minute, timezone letter
    - DDHHMMZMmmYY (e.g., 181430ZFeb26) - with month and year
    - DDHHMMSSZMmmYY (e.g., 05135639ZFeb26) - with seconds
    """
    dtg = dtg_str.strip().upper()

    # Pattern: DD HH MM [SS] Letter [Mmm YY]
    # Examples: 051100Z, 181430ZFEB26, 05135639ZFEB26

    # Try pattern with seconds and date: DDHHMMSSL + MmmYY
    match = re.match(r'^(\d{2})(\d{2})(\d{2})(\d{2})([A-Z])([A-Z]{3})(\d{2})$', dtg)
    if match:
        day, hour, minute, second, tz_letter, month_str, year_short = match.groups()
        month_map = {'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4, 'MAY': 5, 'JUN': 6,
                     'JUL': 7, 'AUG': 8, 'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12}
        month = month_map.get(month_str)
        if not month:
            raise ValueError(f"Invalid month in DTG: {month_str}")
        year = 2000 + int(year_short)
        dt = datetime(year, month, int(day), int(hour), int(minute), int(second))
        return apply_military_offset(dt, tz_letter)

    # Try pattern with date but no seconds: DDHHMML + MmmYY
    match = re.match(r'^(\d{2})(\d{2})(\d{2})([A-Z])([A-Z]{3})(\d{2})$', dtg)
    if match:
        day, hour, minute, tz_letter, month_str, year_short = match.groups()
        month_map = {'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4, 'MAY': 5, 'JUN': 6,
                     'JUL': 7, 'AUG': 8, 'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12}
        month = month_map.get(month_str)
        if not month:
            raise ValueError(f"Invalid month in DTG: {month_str}")
        year = 2000 + int(year_short)
        dt = datetime(year, month, int(day), int(hour), int(minute))
        return apply_military_offset(dt, tz_letter)

    # Try simple pattern: DDHHMML (no date - use current month/year)
    match = re.match(r'^(\d{2})(\d{2})(\d{2})([A-Z])$', dtg)
    if match:
        day, hour, minute, tz_letter = match.groups()
        now = datetime.now()
        dt = datetime(now.year, now.month, int(day), int(hour), int(minute))
        return apply_military_offset(dt, tz_letter)

    raise ValueError(f"Could not parse DTG: {dtg_str}")


def apply_military_offset(dt: datetime, tz_letter: str) -> datetime:
    """Apply military timezone offset to convert to UTC."""
    if tz_letter not in MILITARY_TIMEZONES:
        raise ValueError(f"Invalid military timezone letter: {tz_letter}")

    _, offset_hours = MILITARY_TIMEZONES[tz_letter]
    # Subtract offset to get UTC (if letter is +1, we subtract 1 hour to get UTC)
    dt_utc = dt - timedelta(hours=offset_hours)
    return dt_utc.replace(tzinfo=ZoneInfo("UTC"))


def format_dtg(dt: datetime, include_date: bool = True, include_seconds: bool = False) -> tuple:
    """
    Format datetime to NATO DTG format.

    Returns tuple of (dtg_short, dtg_full, dtg_seconds, military_letter, military_name)
    """
    # Get offset in hours
    offset = dt.utcoffset()
    if offset is None:
        offset_hours = 0
    else:
        offset_hours = int(offset.total_seconds() / 3600)

    # Find military letter for this offset
    military_letter = OFFSET_TO_MILITARY.get(offset_hours, "Z")
    military_name = MILITARY_TIMEZONES.get(military_letter, ("Zulu", 0))[0]

    # Format components
    day = dt.strftime("%d")
    time_hhmm = dt.strftime("%H%M")
    time_hhmmss = dt.strftime("%H%M%S")
    month = dt.strftime("%b")
    year = dt.strftime("%y")

    dtg_short = f"{day}{time_hhmm}{military_letter}"
    dtg_full = f"{day}{time_hhmm}{military_letter}{month}{year}"
    dtg_seconds = f"{day}{time_hhmmss}{military_letter}{month}{year}"

    return dtg_short, dtg_full, dtg_seconds, military_letter, military_name


def parse_timestamp(timestamp_str: str, tz: ZoneInfo) -> datetime:
    """Parse various timestamp formats."""
    # Clean up the string
    ts = timestamp_str.strip()

    # Common Cisco/syslog formats
    formats = [
        "%Y-%m-%dT%H:%M:%S",           # ISO without tz
        "%Y-%m-%dT%H:%M:%S.%f",        # ISO with microseconds
        "%Y-%m-%dT%H:%M:%SZ",          # ISO with Z
        "%Y-%m-%dT%H:%M:%S.%fZ",       # ISO with microseconds and Z
        "%Y-%m-%d %H:%M:%S",           # Simple datetime
        "%Y-%m-%d %H:%M:%S.%f",        # With microseconds
        "%b %d %H:%M:%S",              # Syslog format (no year)
        "%b %d %Y %H:%M:%S",           # Syslog with year
        "%d-%b-%Y %H:%M:%S",           # Cisco format
        "%H:%M:%S",                     # Time only
    ]

    # Handle Z suffix (ZULU)
    if ts.endswith('Z'):
        ts = ts[:-1]
        tz = ZoneInfo("UTC")

    # Handle +/-HH:MM offset
    offset_match = re.search(r'([+-]\d{2}):?(\d{2})$', ts)
    if offset_match:
        ts = ts[:offset_match.start()].strip()

    for fmt in formats:
        try:
            dt = datetime.strptime(ts, fmt)
            # If no year in format, use current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.replace(tzinfo=tz)
        except ValueError:
            continue

    raise ValueError(f"Could not parse timestamp: {timestamp_str}")


def get_tz_label(tz_id: str) -> str:
    """Get friendly label for timezone."""
    for tz in COMMON_TIMEZONES:
        if tz["id"] == tz_id:
            return tz["label"]
    return tz_id


@router.get(
    "/list",
    summary="List common timezones",
    description="Get list of common network-relevant timezones"
)
async def list_timezones() -> List[dict]:
    """List common timezones used in network operations."""
    return COMMON_TIMEZONES


@router.post(
    "/convert",
    response_model=TimezoneConvertResponse,
    summary="Convert timestamp between timezones",
    description="Convert a single timestamp to multiple target timezones"
)
async def convert_timestamp(request: TimezoneConvertRequest) -> TimezoneConvertResponse:
    """
    Convert a timestamp from one timezone to multiple others.

    Supports various input formats:
    - ISO 8601: 2026-02-17T14:30:00Z
    - Simple: 2026-02-17 14:30:00
    - Syslog: Feb 17 14:30:00
    - Cisco: 17-Feb-2026 14:30:00
    """
    try:
        from_tz = ZoneInfo(request.from_timezone)
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Unknown timezone: {request.from_timezone}")

    try:
        dt = parse_timestamp(request.timestamp, from_tz)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Convert to UTC first
    dt_utc = dt.astimezone(ZoneInfo("UTC"))

    results = []
    for tz_id in request.to_timezones:
        try:
            target_tz = ZoneInfo(tz_id)
            dt_converted = dt_utc.astimezone(target_tz)

            results.append(TimezoneResult(
                timezone=tz_id,
                label=get_tz_label(tz_id),
                datetime_iso=dt_converted.isoformat(),
                datetime_formatted=dt_converted.strftime("%Y-%m-%d %H:%M:%S %Z"),
                offset=dt_converted.strftime("%z")
            ))
        except KeyError:
            results.append(TimezoneResult(
                timezone=tz_id,
                label=f"Unknown: {tz_id}",
                datetime_iso="",
                datetime_formatted=f"Error: Unknown timezone {tz_id}",
                offset=""
            ))

    return TimezoneConvertResponse(
        original_input=request.timestamp,
        original_timezone=request.from_timezone,
        parsed_utc=dt_utc.isoformat(),
        results=results
    )


@router.post(
    "/batch",
    summary="Batch convert timestamps",
    description="Convert multiple timestamps from one timezone to another"
)
async def batch_convert(request: BatchConvertRequest) -> List[BatchResult]:
    """
    Convert multiple timestamps at once.
    Useful for correlating logs from different sources.
    """
    try:
        from_tz = ZoneInfo(request.from_timezone)
        to_tz = ZoneInfo(request.to_timezone)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Unknown timezone: {e}")

    results = []
    for ts in request.timestamps:
        try:
            dt = parse_timestamp(ts, from_tz)
            dt_converted = dt.astimezone(to_tz)
            results.append(BatchResult(
                original=ts,
                converted=dt_converted.strftime("%Y-%m-%d %H:%M:%S %Z"),
                success=True
            ))
        except Exception as e:
            results.append(BatchResult(
                original=ts,
                converted="",
                success=False,
                error=str(e)
            ))

    return results


@router.get(
    "/now",
    response_model=NowResponse,
    summary="Current time in all common timezones",
    description="Get the current time in all common network timezones"
)
async def get_current_time() -> NowResponse:
    """Get current time in all common timezones."""
    now_utc = datetime.now(ZoneInfo("UTC"))

    results = []
    for tz_info in COMMON_TIMEZONES:
        tz = ZoneInfo(tz_info["id"])
        dt_local = now_utc.astimezone(tz)

        results.append(TimezoneResult(
            timezone=tz_info["id"],
            label=tz_info["label"],
            datetime_iso=dt_local.isoformat(),
            datetime_formatted=dt_local.strftime("%Y-%m-%d %H:%M:%S %Z"),
            offset=dt_local.strftime("%z")
        ))

    return NowResponse(
        generated_at_utc=now_utc.isoformat(),
        timezones=results
    )


@router.post(
    "/dtg/convert",
    response_model=DTGConvertResponse,
    summary="Convert NATO DTG to timezones",
    description="Parse NATO Date-Time Group and convert to multiple timezones"
)
async def convert_dtg(request: DTGConvertRequest) -> DTGConvertResponse:
    """
    Convert NATO Date-Time Group format to multiple timezones.

    Supported DTG formats:
    - 051100Z (day, time, Zulu)
    - 181430ZFeb26 (with month and year)
    - 05135639ZFeb26 (with seconds)
    """
    try:
        dt_utc = parse_dtg(request.dtg)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Format Zulu DTG
    dtg_short, dtg_full, _, _, _ = format_dtg(dt_utc)

    results = []
    for tz_info in COMMON_TIMEZONES:
        tz = ZoneInfo(tz_info["id"])
        dt_local = dt_utc.astimezone(tz)
        dtg_s, dtg_f, dtg_sec, mil_letter, mil_name = format_dtg(dt_local)

        results.append(DTGResult(
            timezone=tz_info["id"],
            label=tz_info["label"],
            military_letter=mil_letter,
            military_name=mil_name,
            dtg_short=dtg_s,
            dtg_full=dtg_f,
            dtg_seconds=dtg_sec,
            datetime_iso=dt_local.isoformat(),
            datetime_formatted=dt_local.strftime("%Y-%m-%d %H:%M:%S %Z")
        ))

    return DTGConvertResponse(
        original_input=request.dtg,
        parsed_utc=dt_utc.isoformat(),
        dtg_zulu=dtg_full,
        results=results
    )


@router.get(
    "/dtg/now",
    response_model=DTGNowResponse,
    summary="Current time in NATO DTG format",
    description="Get current time as NATO Date-Time Group in all common timezones"
)
async def get_dtg_now() -> DTGNowResponse:
    """Get current time in NATO DTG format for all common timezones."""
    now_utc = datetime.now(ZoneInfo("UTC"))
    dtg_short, dtg_full, _, _, _ = format_dtg(now_utc)

    results = []
    for tz_info in COMMON_TIMEZONES:
        tz = ZoneInfo(tz_info["id"])
        dt_local = now_utc.astimezone(tz)
        dtg_s, dtg_f, dtg_sec, mil_letter, mil_name = format_dtg(dt_local)

        results.append(DTGResult(
            timezone=tz_info["id"],
            label=tz_info["label"],
            military_letter=mil_letter,
            military_name=mil_name,
            dtg_short=dtg_s,
            dtg_full=dtg_f,
            dtg_seconds=dtg_sec,
            datetime_iso=dt_local.isoformat(),
            datetime_formatted=dt_local.strftime("%Y-%m-%d %H:%M:%S %Z")
        ))

    return DTGNowResponse(
        generated_at_utc=now_utc.isoformat(),
        dtg_zulu=dtg_short,
        dtg_zulu_full=dtg_full,
        timezones=results
    )
