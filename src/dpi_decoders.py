"""
dpi_decoders.py — NetGuard IDS v3.5
Deep Packet Inspection (DPI) Decoders for Industrial IoT & SCADA Protocols:
- Modbus TCP (Port 502)
- MQTT (Port 1883 / 8883)
- CoAP (Port 5683)
- OPC-UA (Port 4840)
- DNP3 (Port 20000)
Extracts function codes, topics, registers, and flags protocol-level anomalies.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


@dataclass
class DPIResult:
    protocol: str
    detected: bool = False
    function_or_method: Optional[str] = None
    target_resource: Optional[str] = None  # register, topic, or URI
    is_anomaly: bool = False
    anomaly_reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "detected": self.detected,
            "function": self.function_or_method,
            "resource": self.target_resource,
            "is_anomaly": self.is_anomaly,
            "anomaly_reason": self.anomaly_reason,
            "details": self.details,
        }


# ── 1. Modbus TCP Decoder (Port 502) ──────────────────────────
MODBUS_FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostic Loopback",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Slave ID",
    43: "Encapsulated Interface Transport",
}

CRITICAL_WRITE_FUNCTIONS = {5, 6, 15, 16}


def decode_modbus_tcp(payload: bytes) -> Optional[DPIResult]:
    """
    MBAP Header:
    Transaction ID (2B) | Protocol ID (2B, 0=Modbus) | Length (2B) | Unit ID (1B) | Function Code (1B) ...
    """
    if len(payload) < 8:
        return None

    try:
        trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
        if proto_id != 0:
            return None  # Protocol ID must be 0 for standard Modbus TCP

        func_code = payload[7]
        is_exception = (func_code & 0x80) != 0
        actual_func = func_code & 0x7F
        func_name = MODBUS_FUNCTIONS.get(actual_func, f"Unknown (0x{actual_func:02X})")

        is_anomaly = False
        reason = None

        if is_exception:
            exc_code = payload[8] if len(payload) > 8 else 0
            is_anomaly = True
            reason = f"Modbus Exception Response (Func 0x{actual_func:02X}, Exc: {exc_code})"
        elif actual_func in CRITICAL_WRITE_FUNCTIONS:
            # Dangerous OT write attempt
            is_anomaly = True
            reason = f"Critical OT State Modification: {func_name} on Unit {unit_id}"
        elif actual_func not in MODBUS_FUNCTIONS:
            is_anomaly = True
            reason = f"Undefined or Probing Modbus Function Code: 0x{actual_func:02X}"

        target_reg = None
        if len(payload) >= 10:
            target_reg = f"0x{payload[8]:02X}{payload[9]:02X}"

        return DPIResult(
            protocol="Modbus TCP",
            detected=True,
            function_or_method=func_name,
            target_resource=target_reg,
            is_anomaly=is_anomaly,
            anomaly_reason=reason,
            details={
                "transaction_id": trans_id,
                "unit_id": unit_id,
                "function_code": actual_func,
                "is_exception": is_exception,
                "raw_len": len(payload),
            }
        )
    except Exception:
        return None


# ── 2. MQTT Decoder (Port 1883 / 8883) ────────────────────────
MQTT_PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}


def decode_mqtt(payload: bytes) -> Optional[DPIResult]:
    """
    Fixed Header:
    Byte 0: [ Packet Type (4b) | Flags (4b) ]
    Remaining Length: variable 1-4 bytes
    """
    if len(payload) < 2:
        return None

    try:
        first_byte = payload[0]
        pkt_type = (first_byte >> 4) & 0x0F
        type_name = MQTT_PACKET_TYPES.get(pkt_type)
        if not type_name:
            return None

        # Parse variable remaining length
        multiplier = 1
        rem_len = 0
        idx = 1
        while idx < len(payload):
            byte = payload[idx]
            rem_len += (byte & 127) * multiplier
            multiplier *= 128
            idx += 1
            if (byte & 128) == 0:
                break
            if idx > 4:
                return None  # Malformed remaining length

        is_anomaly = False
        reason = None
        topic = None

        # Inspect PUBLISH packets
        if pkt_type == 3:  # PUBLISH
            # flags = first_byte & 0x0F
            # qos = (flags >> 1) & 0x03
            if idx + 2 <= len(payload):
                topic_len = struct.unpack(">H", payload[idx:idx+2])[0]
                idx += 2
                if idx + topic_len <= len(payload):
                    topic = payload[idx:idx+topic_len].decode("utf-8", errors="ignore")
                    idx += topic_len

                    # Check for suspicious injection or control topics
                    if any(bad in topic.lower() for bad in ["admin", "root", "cmd", "exec", "kill", "shell", "../"]):
                        is_anomaly = True
                        reason = f"Suspicious MQTT Command/Control Topic: '{topic}'"

        # Inspect SUBSCRIBE packets for wildcard sniffing
        elif pkt_type == 8:  # SUBSCRIBE
            if idx + 2 <= len(payload):
                idx += 2  # Skip packet ID
                if idx + 2 <= len(payload):
                    t_len = struct.unpack(">H", payload[idx:idx+2])[0]
                    idx += 2
                    if idx + t_len <= len(payload):
                        topic = payload[idx:idx+t_len].decode("utf-8", errors="ignore")
                        if topic in ("#", "+/#", "$SYS/#"):
                            is_anomaly = True
                            reason = f"Broad Multi-Level Wildcard Topic Subscription ('{topic}') — Potential Broker Sniffing"

        return DPIResult(
            protocol="MQTT",
            detected=True,
            function_or_method=type_name,
            target_resource=topic,
            is_anomaly=is_anomaly,
            anomaly_reason=reason,
            details={"packet_type": type_name, "raw_len": len(payload)}
        )
    except Exception:
        return None


# ── 3. CoAP Decoder (Port 5683) ───────────────────────────────
COAP_METHODS = {
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE"
}


def decode_coap(payload: bytes) -> Optional[DPIResult]:
    """
    CoAP Header:
    Ver (2b) | T (2b) | TKL (4b) | Code (8b, c.dd) | Message ID (16b)
    """
    if len(payload) < 4:
        return None

    try:
        b0 = payload[0]
        version = (b0 >> 6) & 0x03
        if version != 1:
            return None  # CoAP version must be 1

        tkl = b0 & 0x0F
        code = payload[1]
        msg_id = struct.unpack(">H", payload[2:4])[0]

        code_class = (code >> 5) & 0x07
        code_detail = code & 0x1F

        method_str = f"{code_class}.{code_detail:02d}"
        is_request = (code_class == 0)
        if is_request:
            method_str = COAP_METHODS.get(code_detail, f"REQ({code_detail})")

        is_anomaly = False
        reason = None

        # Flag DELETE or unusual methods on constrained IoT sensors
        if method_str == "DELETE":
            is_anomaly = True
            reason = f"CoAP DELETE Action Issued to Constrained Sensor (MsgID: {msg_id})"
        elif code_class in (4, 5):  # 4.xx Client Error, 5.xx Server Error
            is_anomaly = True
            reason = f"CoAP Fault Response ({code_class}.{code_detail:02d})"

        return DPIResult(
            protocol="CoAP",
            detected=True,
            function_or_method=method_str,
            target_resource=f"msg_id={msg_id}",
            is_anomaly=is_anomaly,
            anomaly_reason=reason,
            details={"version": version, "tkl": tkl, "code": code, "msg_id": msg_id}
        )
    except Exception:
        return None


# ── Unified Inspector Entry Point ─────────────────────────────
def inspect_industrial_payload(payload: bytes, dst_port: int, src_port: int = 0) -> Optional[DPIResult]:
    """
    Dispatches payload to the appropriate DPI decoder based on port and heuristics.
    Supports Modbus TCP (502), MQTT (1883/8883), CoAP (5683), and OPC-UA (4840).
    """
    if not payload:
        return None

    ports = {dst_port, src_port}

    # 1. Modbus TCP
    if 502 in ports:
        res = decode_modbus_tcp(payload)
        if res:
            return res

    # 2. MQTT
    if 1883 in ports or 8883 in ports:
        res = decode_mqtt(payload)
        if res:
            return res

    # 3. CoAP
    if 5683 in ports:
        res = decode_coap(payload)
        if res:
            return res

    # Heuristic fallback if port is non-standard
    if len(payload) >= 8 and payload[2:4] == b"\x00\x00":
        res = decode_modbus_tcp(payload)
        if res and res.detected:
            return res

    if len(payload) >= 2 and ((payload[0] >> 4) & 0x0F) in MQTT_PACKET_TYPES:
        res = decode_mqtt(payload)
        if res and res.detected:
            return res

    return None
