"""
Timezone Converter API Router
Convert timestamps between timezones - essential for log correlation.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from zoneinfo import ZoneInfo, available_timezones
import re

router = APIRouter(prefix="/tools/timezone", tags=["Timezone Converter"])

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
