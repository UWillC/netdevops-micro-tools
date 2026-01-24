from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import datetime

router = APIRouter()


# -----------------------------
# iPerf3 Command Generator Schema
# -----------------------------
class IPerfRequest(BaseModel):
    # Link speed
    link_speed: str = "1g"  # 100m / 1g / 10g

    # Test type
    test_type: str = "tcp"  # tcp / udp / both

    # Server settings
    server_ip: str
    port: int = 5201
    port_secondary: int = 5202  # For "both" mode

    # Test parameters
    duration: int = 60  # seconds
    interval: int = 10  # reporting interval
    direction: str = "upload"  # upload / download / bidirectional

    # TCP options
    parallel_streams: int = 4  # -P for TCP

    # UDP options
    target_bandwidth: Optional[str] = None  # Auto-calculated if None

    # Output options
    json_output: bool = True
    output_filename: Optional[str] = None

    # Output format
    output_format: str = "cli"  # cli / script


# -----------------------------
# Bandwidth calculation based on link speed
# -----------------------------
def get_bandwidth_for_link(link_speed: str, direction: str) -> str:
    """Calculate appropriate bandwidth for UDP tests"""
    bandwidth_map = {
        "100m": {"upload": "90M", "download": "90M", "bidirectional": "45M"},
        "1g": {"upload": "900M", "download": "900M", "bidirectional": "450M"},
        "10g": {"upload": "9G", "download": "9G", "bidirectional": "4.5G"},
    }
    return bandwidth_map.get(link_speed, bandwidth_map["1g"]).get(direction, "900M")


def get_link_speed_label(link_speed: str) -> str:
    """Human readable link speed"""
    labels = {"100m": "100 Mbps", "1g": "1 Gbps", "10g": "10 Gbps"}
    return labels.get(link_speed, "1 Gbps")


# -----------------------------
# Command generators
# -----------------------------
def generate_server_command(port: int, json_output: bool = False) -> str:
    """Generate iperf3 server command"""
    cmd = f"iperf3 -s -p {port}"
    if json_output:
        cmd += f" --logfile iperf_server_{port}.log"
    return cmd


def generate_tcp_client_command(req: IPerfRequest, direction: str) -> str:
    """Generate TCP client command"""
    cmd = f"iperf3 -c {req.server_ip} -p {req.port}"
    cmd += f" -P {req.parallel_streams}"
    cmd += f" -t {req.duration}"
    cmd += f" -i {req.interval}"

    if direction == "download":
        cmd += " -R"
    elif direction == "bidirectional":
        cmd += " --bidir"

    if req.json_output:
        cmd += " -J"
        if req.output_filename:
            cmd += f" > {req.output_filename}"
        else:
            filename = f"tcp_{req.link_speed}_{direction}_{req.duration}s.json"
            cmd += f" > {filename}"

    cmd += " --timestamps"
    return cmd


def generate_udp_client_command(req: IPerfRequest, direction: str, port: int = None) -> str:
    """Generate UDP client command"""
    use_port = port or req.port
    bandwidth = req.target_bandwidth or get_bandwidth_for_link(req.link_speed, direction)

    cmd = f"iperf3 -c {req.server_ip} -p {use_port}"
    cmd += " -u"
    cmd += f" -b {bandwidth}"
    cmd += f" -t {req.duration}"
    cmd += f" -i {req.interval}"

    if direction == "download":
        cmd += " -R"
    elif direction == "bidirectional":
        cmd += " --bidir"

    if req.json_output:
        cmd += " -J"
        if req.output_filename:
            cmd += f" > {req.output_filename}"
        else:
            filename = f"udp_{req.link_speed}_{direction}_{req.duration}s.json"
            cmd += f" > {filename}"

    cmd += " --timestamps"
    return cmd


# -----------------------------
# Main generator
# -----------------------------
def generate_iperf_commands(req: IPerfRequest) -> str:
    """Generate complete iperf3 command set"""
    lines = []
    link_label = get_link_speed_label(req.link_speed)
    duration_min = req.duration // 60 if req.duration >= 60 else f"{req.duration}s"
    if isinstance(duration_min, int):
        duration_label = f"{duration_min} min" if duration_min > 0 else f"{req.duration}s"
    else:
        duration_label = duration_min

    # Header
    lines.append("# ============================================")
    lines.append(f"# iPerf3 Network Test - {link_label}")
    lines.append(f"# Test Type: {req.test_type.upper()}")
    lines.append(f"# Direction: {req.direction}")
    lines.append(f"# Duration: {duration_label}")
    lines.append(f"# Server: {req.server_ip}")
    lines.append("# ============================================")
    lines.append("")

    # Server commands
    lines.append("# --- SERVER SIDE ---")
    lines.append(f"# Run on server ({req.server_ip}):")
    lines.append("")

    if req.test_type == "tcp":
        lines.append(generate_server_command(req.port))
    elif req.test_type == "udp":
        lines.append(generate_server_command(req.port))
    else:  # both
        lines.append(f"# Terminal 1 - TCP (port {req.port}):")
        lines.append(generate_server_command(req.port))
        lines.append("")
        lines.append(f"# Terminal 2 - UDP (port {req.port_secondary}):")
        lines.append(generate_server_command(req.port_secondary))

    lines.append("")

    # Client commands
    lines.append("# --- CLIENT SIDE ---")
    lines.append("# Run on client:")
    lines.append("")

    if req.test_type == "tcp":
        lines.append("# TCP Throughput Test:")
        lines.append(generate_tcp_client_command(req, req.direction))

    elif req.test_type == "udp":
        bandwidth = req.target_bandwidth or get_bandwidth_for_link(req.link_speed, req.direction)
        lines.append(f"# UDP Test (target: {bandwidth}):")
        lines.append(generate_udp_client_command(req, req.direction))

    else:  # both
        lines.append("# TCP Throughput Test (Terminal 1):")
        lines.append(generate_tcp_client_command(req, req.direction))
        lines.append("")
        bandwidth = req.target_bandwidth or get_bandwidth_for_link(req.link_speed, req.direction)
        lines.append(f"# UDP Jitter/Loss Test (Terminal 2, target: {bandwidth}):")
        lines.append(generate_udp_client_command(req, req.direction, req.port_secondary))

    lines.append("")

    # Expected results hint
    lines.append("# --- EXPECTED RESULTS ---")
    if req.test_type in ["tcp", "both"]:
        lines.append(f"# TCP: ~{get_expected_throughput(req.link_speed)} throughput, <0.1% retransmits")
    if req.test_type in ["udp", "both"]:
        lines.append(f"# UDP: <1ms jitter, <0.1% packet loss")

    return "\n".join(lines)


def get_expected_throughput(link_speed: str) -> str:
    """Get expected throughput for link speed"""
    expected = {"100m": "94-96 Mbps", "1g": "940-960 Mbps", "10g": "9.4-9.6 Gbps"}
    return expected.get(link_speed, "940-960 Mbps")


def generate_iperf_script(req: IPerfRequest) -> str:
    """Generate PowerShell/Bash script for complete test"""
    lines = []
    link_label = get_link_speed_label(req.link_speed)

    lines.append("#!/bin/bash")
    lines.append("# iPerf3 Automated Test Script")
    lines.append(f"# Link: {link_label} | Type: {req.test_type.upper()} | Duration: {req.duration}s")
    lines.append("")
    lines.append(f'SERVER="{req.server_ip}"')
    lines.append(f"PORT={req.port}")
    lines.append(f"DURATION={req.duration}")
    lines.append(f"INTERVAL={req.interval}")
    lines.append('TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")')
    lines.append('OUTPUT_DIR="./iperf_results"')
    lines.append("")
    lines.append("# Create output directory")
    lines.append('mkdir -p "$OUTPUT_DIR"')
    lines.append("")
    lines.append('echo "Starting iPerf3 test..."')
    lines.append(f'echo "Server: $SERVER | Duration: {req.duration}s"')
    lines.append("")

    if req.test_type == "tcp":
        lines.append("# TCP Test")
        cmd = f'iperf3 -c "$SERVER" -p $PORT -P {req.parallel_streams} -t $DURATION -i $INTERVAL'
        if req.direction == "download":
            cmd += " -R"
        elif req.direction == "bidirectional":
            cmd += " --bidir"
        cmd += ' -J --timestamps > "$OUTPUT_DIR/tcp_${TIMESTAMP}.json"'
        lines.append(cmd)

    elif req.test_type == "udp":
        bandwidth = req.target_bandwidth or get_bandwidth_for_link(req.link_speed, req.direction)
        lines.append("# UDP Test")
        cmd = f'iperf3 -c "$SERVER" -p $PORT -u -b {bandwidth} -t $DURATION -i $INTERVAL'
        if req.direction == "download":
            cmd += " -R"
        elif req.direction == "bidirectional":
            cmd += " --bidir"
        cmd += ' -J --timestamps > "$OUTPUT_DIR/udp_${TIMESTAMP}.json"'
        lines.append(cmd)

    else:  # both
        bandwidth = req.target_bandwidth or get_bandwidth_for_link(req.link_speed, req.direction)
        lines.append("# Run TCP and UDP tests")
        lines.append("echo 'Starting TCP test...'")
        tcp_cmd = f'iperf3 -c "$SERVER" -p $PORT -P {req.parallel_streams} -t $DURATION -i $INTERVAL'
        if req.direction == "download":
            tcp_cmd += " -R"
        elif req.direction == "bidirectional":
            tcp_cmd += " --bidir"
        tcp_cmd += ' -J --timestamps > "$OUTPUT_DIR/tcp_${TIMESTAMP}.json"'
        lines.append(tcp_cmd)
        lines.append("")
        lines.append("echo 'Starting UDP test...'")
        udp_cmd = f'iperf3 -c "$SERVER" -p {req.port_secondary} -u -b {bandwidth} -t $DURATION -i $INTERVAL'
        if req.direction == "download":
            udp_cmd += " -R"
        elif req.direction == "bidirectional":
            udp_cmd += " --bidir"
        udp_cmd += ' -J --timestamps > "$OUTPUT_DIR/udp_${TIMESTAMP}.json"'
        lines.append(udp_cmd)

    lines.append("")
    lines.append('echo "Test complete. Results saved to $OUTPUT_DIR"')

    return "\n".join(lines)


# -----------------------------
# API Endpoint
# -----------------------------
@router.post("/iperf")
def generate_iperf(req: IPerfRequest):
    if req.output_format == "script":
        output = generate_iperf_script(req)
    else:
        output = generate_iperf_commands(req)

    return {
        "link_speed": req.link_speed,
        "test_type": req.test_type,
        "direction": req.direction,
        "duration": req.duration,
        "output_format": req.output_format,
        "config": output,
        "metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "module": "iPerf3 Command Generator",
            "tool": "NetDevOps Micro-Tools",
        },
    }
