#!/usr/bin/env python3
"""
generate_dataset.py

Builds a flow-level CSV dataset for the project:
"Malware Detection Using JA4 Fingerprints and a 1D CNN"

It walks a directory of .pcap / .pcapng files belonging to one or more
malware families, groups packets into flows keyed by
(src_ip, dst_ip, src_port, dst_port, protocol), computes statistical /
protocol / TLS (JA3 & JA4) / DNS / HTTP features per flow, joins each
file to its metadata (sample hash + label) from metadata.txt, and
writes everything to a single CSV.

Usage:
    python3 generate_dataset.py \
        --input-dir /path/to/pcaps \
        --metadata /path/to/metadata.txt \
        --output dataset.csv

metadata.txt format (CSV, header required):
    pcap_file,sample_hash,label
    trickbot_001.pcapng,abcdef123456,trickbot
    trickbot_002.pcapng,xyz987654321,trickbot

Requires: scapy (pip install scapy --break-system-packages)
Tested on Python 3.12/3.13 + scapy 2.7.
"""

import argparse
import csv
import glob
import hashlib
import os
import re
import statistics
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.packet import Raw


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CSV_FIELDNAMES = [
    # metadata
    "pcap_id",
    "sample_hash",
    "label",
    # flow identity
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    # timing / volume features
    "duration",
    "total_bytes",
    "total_packets",
    "bytes_per_second",
    "packets_per_second",
    "pkt_len_mean",
    "pkt_len_std",
    "iat_mean",
    "iat_std",
    "burstiness",
    "burst_count",
    "is_complete_handshake",
    # TLS (generic)
    "has_tls",
    "tls_cipher_count",
    "tls_ext_count",
    # JA4
    "ja4_fingerprint",
    "ja4_tls_ver_num",
    "ja4_cipher_count",
    "ja4_ext_count",
    "ja4_sni_present",
    "ja4_has_alpn",
    # JA3
    "ja3_fingerprint",
    # DNS
    "dns_query_count",
    "dns_unique_queries",
    # HTTP
    "http_request_count",
    "http_unique_hosts",
]

# GREASE values (RFC 8701) that must be excluded from JA3/JA4 hashing.
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Mapping from raw 2-byte TLS version value -> JA4 version token.
JA4_VERSION_TOKEN = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}
# Numeric representation used for the ja4_tls_ver_num column.
JA4_VERSION_NUM = {"13": 13, "12": 12, "11": 11, "10": 10, "s3": 3, "s2": 2, "s1": 1}

HTTP_METHOD_RE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|TRACE|PATCH)\s+\S+\s+HTTP/\d\.\d", re.IGNORECASE)
HTTP_HOST_RE = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)

TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_CLIENT_HELLO_TYPE = 0x01

EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B


# --------------------------------------------------------------------------- #
# TLS ClientHello manual parsing (no dependency on scapy's TLS layer, which
# requires load_layer('tls') and extra crypto deps we don't need here since we
# never decrypt anything -- we only need the ClientHello for JA3/JA4).
# --------------------------------------------------------------------------- #

@dataclass
class TLSClientHelloInfo:
    client_version: int
    ciphers: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    sni: Optional[str] = None
    alpn: List[str] = field(default_factory=list)
    sig_algs: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)


def parse_tls_client_hello(payload: bytes) -> Optional[TLSClientHelloInfo]:
    """
    Best-effort manual parser for a TLS ClientHello embedded in a TCP payload.
    Returns None if the payload doesn't look like a (plaintext) ClientHello,
    or if parsing fails for any reason. Never raises.
    """
    try:
        if len(payload) < 9:
            return None
        if payload[0] != TLS_HANDSHAKE_CONTENT_TYPE:
            return None
        # record header: type(1) version(2) length(2)
        pos = 5
        if payload[pos] != TLS_CLIENT_HELLO_TYPE:
            return None
        # handshake header: type(1) length(3)
        pos += 4

        if len(payload) < pos + 2:
            return None
        client_version = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2

        pos += 32  # random (32 bytes)
        if len(payload) < pos + 1:
            return None

        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if len(payload) < pos + 2:
            return None
        cipher_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        ciphers = []
        end = pos + cipher_len
        while pos + 2 <= min(end, len(payload)):
            ciphers.append(struct.unpack(">H", payload[pos:pos + 2])[0])
            pos += 2
        pos = end

        if len(payload) < pos + 1:
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        extensions: List[int] = []
        sni = None
        alpn: List[str] = []
        sig_algs: List[int] = []
        supported_groups: List[int] = []
        ec_point_formats: List[int] = []
        supported_versions: List[int] = []

        if pos + 2 <= len(payload):
            ext_total_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2
            ext_end = min(pos + ext_total_len, len(payload))

            while pos + 4 <= ext_end:
                ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
                ext_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
                data_start = pos + 4
                data_end = min(data_start + ext_len, len(payload))
                ext_data = payload[data_start:data_end]
                extensions.append(ext_type)

                try:
                    if ext_type == EXT_SNI and len(ext_data) >= 2:
                        sub_pos = 2  # skip server_name_list length
                        while sub_pos + 3 <= len(ext_data):
                            name_type = ext_data[sub_pos]
                            name_len = struct.unpack(">H", ext_data[sub_pos + 1:sub_pos + 3])[0]
                            name = ext_data[sub_pos + 3:sub_pos + 3 + name_len]
                            if name_type == 0:
                                sni = name.decode("utf-8", errors="ignore")
                            sub_pos += 3 + name_len
                    elif ext_type == EXT_ALPN and len(ext_data) >= 2:
                        sub_pos = 2  # skip protocol_name_list length
                        while sub_pos + 1 <= len(ext_data):
                            proto_len = ext_data[sub_pos]
                            proto = ext_data[sub_pos + 1:sub_pos + 1 + proto_len]
                            if proto:
                                alpn.append(proto.decode("utf-8", errors="ignore"))
                            sub_pos += 1 + proto_len
                    elif ext_type == EXT_SIGNATURE_ALGORITHMS and len(ext_data) >= 2:
                        sub_pos = 2
                        while sub_pos + 2 <= len(ext_data):
                            sig_algs.append(struct.unpack(">H", ext_data[sub_pos:sub_pos + 2])[0])
                            sub_pos += 2
                    elif ext_type == EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                        sub_pos = 2
                        while sub_pos + 2 <= len(ext_data):
                            supported_groups.append(struct.unpack(">H", ext_data[sub_pos:sub_pos + 2])[0])
                            sub_pos += 2
                    elif ext_type == EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                        fmt_len = ext_data[0]
                        ec_point_formats.extend(list(ext_data[1:1 + fmt_len]))
                    elif ext_type == EXT_SUPPORTED_VERSIONS and len(ext_data) >= 1:
                        sub_pos = 1  # skip list length byte
                        while sub_pos + 2 <= len(ext_data):
                            supported_versions.append(struct.unpack(">H", ext_data[sub_pos:sub_pos + 2])[0])
                            sub_pos += 2
                except Exception:
                    # Malformed extension body: keep the extension type we
                    # already recorded, ignore its (corrupt) content.
                    pass

                pos = data_start + ext_len

        return TLSClientHelloInfo(
            client_version=client_version,
            ciphers=ciphers,
            extensions=extensions,
            sni=sni,
            alpn=alpn,
            sig_algs=sig_algs,
            supported_groups=supported_groups,
            ec_point_formats=ec_point_formats,
            supported_versions=supported_versions,
        )
    except Exception:
        return None


def compute_ja3(info: TLSClientHelloInfo) -> str:
    """Classic JA3 fingerprint (md5 of version,ciphers,extensions,curves,formats)."""
    ciphers = [c for c in info.ciphers if c not in GREASE_VALUES]
    exts = [e for e in info.extensions if e not in GREASE_VALUES]
    curves = [g for g in info.supported_groups if g not in GREASE_VALUES]
    formats = list(info.ec_point_formats)

    ja3_str = "{ver},{ciphers},{exts},{curves},{formats}".format(
        ver=info.client_version,
        ciphers="-".join(str(c) for c in ciphers),
        exts="-".join(str(e) for e in exts),
        curves="-".join(str(c) for c in curves),
        formats="-".join(str(f) for f in formats),
    )
    return hashlib.md5(ja3_str.encode("utf-8")).hexdigest()


def compute_ja4(info: TLSClientHelloInfo, transport: str = "t") -> Dict[str, object]:
    """
    Best-effort implementation of the JA4 fingerprint (FoxIO) for a TCP TLS
    ClientHello. Returns a dict with the fingerprint plus its numeric
    sub-components so they can be stored as separate dataset columns.

    Note: this is a research-grade re-implementation based on the public JA4
    specification; it is not guaranteed to be byte-identical to every edge
    case of the official reference implementation, but follows the same
    construction (JA4_a + "_" + JA4_b + "_" + JA4_c).
    """
    ciphers_ng = [c for c in info.ciphers if c not in GREASE_VALUES]
    exts_ng = [e for e in info.extensions if e not in GREASE_VALUES]

    # Version: prefer the max value advertised in supported_versions ext.
    version_candidates = [v for v in info.supported_versions if v not in GREASE_VALUES]
    version_val = max(version_candidates) if version_candidates else info.client_version
    ver_token = JA4_VERSION_TOKEN.get(version_val, "00")
    ver_num = JA4_VERSION_NUM.get(ver_token, 0)

    sni_flag = "d" if info.sni else "i"
    cipher_count = min(len(ciphers_ng), 99)
    ext_count = min(len(exts_ng), 99)

    if info.alpn:
        first_alpn = info.alpn[0]
        if len(first_alpn) >= 2:
            alpn_part = first_alpn[0] + first_alpn[-1]
        elif len(first_alpn) == 1:
            alpn_part = first_alpn[0] + first_alpn[0]
        else:
            alpn_part = "00"
    else:
        alpn_part = "00"

    ja4_a = "{proto}{ver}{sni}{cc:02d}{ec:02d}{alpn}".format(
        proto=transport, ver=ver_token, sni=sni_flag,
        cc=cipher_count, ec=ext_count, alpn=alpn_part,
    )

    if ciphers_ng:
        b_input = ",".join(f"{c:04x}" for c in sorted(ciphers_ng))
        ja4_b = hashlib.sha256(b_input.encode()).hexdigest()[:12]
    else:
        ja4_b = "0" * 12

    ext_for_c = sorted(e for e in exts_ng if e not in (EXT_SNI, EXT_ALPN))
    ext_str = ",".join(f"{e:04x}" for e in ext_for_c)
    sigalg_str = ",".join(f"{s:04x}" for s in info.sig_algs)
    if ext_for_c or info.sig_algs:
        c_input = ext_str + "_" + sigalg_str
        ja4_c = hashlib.sha256(c_input.encode()).hexdigest()[:12]
    else:
        ja4_c = "0" * 12

    fingerprint = f"{ja4_a}_{ja4_b}_{ja4_c}"

    return {
        "ja4_fingerprint": fingerprint,
        "ja4_tls_ver_num": ver_num,
        "ja4_cipher_count": len(ciphers_ng),
        "ja4_ext_count": len(exts_ng),
        "ja4_sni_present": 1 if info.sni else 0,
        "ja4_has_alpn": 1 if info.alpn else 0,
    }


# --------------------------------------------------------------------------- #
# Metadata loading
# --------------------------------------------------------------------------- #

class MetadataLoader:
    """Loads pcap_file -> (sample_hash, label) mappings from metadata.txt."""

    def __init__(self, metadata_path: str):
        self.metadata_path = metadata_path
        self.records: Dict[str, Tuple[str, str]] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.isfile(self.metadata_path):
            print(f"[WARN] metadata file not found: {self.metadata_path}")
            return
        with open(self.metadata_path, "r", newline="") as f:
            reader = f.read()      
            rows = reader.split('\n')
        if not rows:
            return
        header = [h.strip().lower() for h in rows[0]]
        start_idx = 1
        if header != ["pcap_file", "sample_hash", "label"]:
            # No recognizable header; assume the file has no header row.
            start_idx = 0
        for row in rows[start_idx:]:
            if len(row.split(',')) < 3:
                continue
            pcap_file, sample_hash, label = (row.split(',')[i].strip() for i in range(3))
            print(pcap_file, sample_hash, label)
            if pcap_file:
                self.records[pcap_file] = (sample_hash, label)

    def lookup(self, filename: str) -> Tuple[str, str]:
        if filename in self.records:
            return self.records[filename]
        print(f"[WARN] no metadata entry for '{filename}', using defaults ('', 'unknown')")
        return "", "unknown"


# --------------------------------------------------------------------------- #
# Flow key & handshake tracking
# --------------------------------------------------------------------------- #

FlowKey = Tuple[str, str, int, int, str]  # src_ip, dst_ip, src_port, dst_port, protocol


def canonical_connection_key(src_ip: str, dst_ip: str, sport: int, dport: int, protocol: str) -> Tuple:
    """
    Undirected key used only to track TCP handshake completeness across BOTH
    directions of a connection, independent of the directional flow rows
    required by the dataset spec.
    """
    endpoints = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
    return (endpoints, protocol)


class HandshakeTracker:
    """Tracks SYN / SYN-ACK / ACK flags per (undirected) TCP connection."""

    def __init__(self):
        self._state: Dict[Tuple, Dict[str, bool]] = defaultdict(
            lambda: {"syn": False, "syn_ack": False, "ack_after_synack": False}
        )

    def observe(self, key: Tuple, flags: str, syn_seen_before: bool) -> None:
        st = self._state[key]
        is_syn = "S" in flags and "A" not in flags
        is_synack = "S" in flags and "A" in flags
        is_ack = flags == "A"
        if is_syn:
            st["syn"] = True
        elif is_synack:
            if st["syn"]:
                st["syn_ack"] = True
        elif is_ack:
            if st["syn_ack"]:
                st["ack_after_synack"] = True

    def is_complete(self, key: Tuple) -> bool:
        st = self._state.get(key)
        if not st:
            return False
        return st["syn"] and st["syn_ack"] and st["ack_after_synack"]


# --------------------------------------------------------------------------- #
# Per-flow feature accumulator
# --------------------------------------------------------------------------- #

class FlowStats:
    """Accumulates packet-level data for one directional flow and produces
    the final feature dict when finalized."""

    def __init__(self, key: FlowKey):
        self.key = key
        self.timestamps: List[float] = []
        self.lengths: List[int] = []

        self.tls_info: Optional[TLSClientHelloInfo] = None  # first ClientHello seen

        self.dns_queries: List[str] = []

        self.http_request_count = 0
        self.http_hosts: set = set()

        self.conn_key: Optional[Tuple] = None  # for handshake lookup

    def add_packet(self, ts: float, length: int) -> None:
        self.timestamps.append(ts)
        self.lengths.append(length)

    def maybe_set_tls(self, info: TLSClientHelloInfo) -> None:
        if self.tls_info is None:
            self.tls_info = info

    def add_dns(self, qname: str) -> None:
        self.dns_queries.append(qname)

    def add_http_request(self, host: Optional[str]) -> None:
        self.http_request_count += 1
        if host:
            self.http_hosts.add(host)

    def finalize(self, handshake_tracker: HandshakeTracker) -> Dict[str, object]:
        src_ip, dst_ip, src_port, dst_port, protocol = self.key

        n = len(self.timestamps)
        total_packets = n
        total_bytes = sum(self.lengths)

        if n >= 1:
            first_ts, last_ts = min(self.timestamps), max(self.timestamps)
            duration = max(last_ts - first_ts, 0.0)
        else:
            duration = 0.0

        rate_denominator = duration if duration > 0 else 1.0
        bytes_per_second = total_bytes / rate_denominator
        packets_per_second = total_packets / rate_denominator

        if self.lengths:
            pkt_len_mean = statistics.mean(self.lengths)
            pkt_len_std = statistics.pstdev(self.lengths) if len(self.lengths) > 1 else 0.0
        else:
            pkt_len_mean = 0.0
            pkt_len_std = 0.0

        sorted_ts = sorted(self.timestamps)
        iats = [t2 - t1 for t1, t2 in zip(sorted_ts, sorted_ts[1:])]
        if iats:
            iat_mean = statistics.mean(iats)
            iat_std = statistics.pstdev(iats) if len(iats) > 1 else 0.0
        else:
            iat_mean = 0.0
            iat_std = 0.0

        denom = iat_mean + iat_std
        burstiness = (iat_std - iat_mean) / denom if denom > 0 else 0.0

        # Heuristic burst detection: a "burst" is a run of consecutive
        # inter-arrival times below the flow's own mean IAT (or a small
        # fixed threshold when the mean is 0/undefined). burst_count counts
        # how many separate bursts occur in the flow.
        burst_count = 0
        if iats:
            threshold = iat_mean if iat_mean > 0 else 0.01
            in_burst = False
            for gap in iats:
                if gap < threshold:
                    if not in_burst:
                        burst_count += 1
                        in_burst = True
                else:
                    in_burst = False

        is_complete_handshake = 0
        if protocol == "TCP" and self.conn_key is not None:
            is_complete_handshake = 1 if handshake_tracker.is_complete(self.conn_key) else 0

        row = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "duration": round(duration, 6),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "bytes_per_second": round(bytes_per_second, 4),
            "packets_per_second": round(packets_per_second, 4),
            "pkt_len_mean": round(pkt_len_mean, 4),
            "pkt_len_std": round(pkt_len_std, 4),
            "iat_mean": round(iat_mean, 6),
            "iat_std": round(iat_std, 6),
            "burstiness": round(burstiness, 6),
            "burst_count": burst_count,
            "is_complete_handshake": is_complete_handshake,
            "dns_query_count": len(self.dns_queries),
            "dns_unique_queries": len(set(self.dns_queries)),
            "http_request_count": self.http_request_count,
            "http_unique_hosts": len(self.http_hosts),
        }

        if self.tls_info is not None:
            ja4_fields = compute_ja4(self.tls_info)
            row.update({
                "has_tls": 1,
                "tls_cipher_count": len(self.tls_info.ciphers),
                "tls_ext_count": len(self.tls_info.extensions),
                "ja3_fingerprint": compute_ja3(self.tls_info),
                **ja4_fields,
            })
        else:
            row.update({
                "has_tls": 0,
                "tls_cipher_count": 0,
                "tls_ext_count": 0,
                "ja3_fingerprint": "",
                "ja4_fingerprint": "",
                "ja4_tls_ver_num": 0,
                "ja4_cipher_count": 0,
                "ja4_ext_count": 0,
                "ja4_sni_present": 0,
                "ja4_has_alpn": 0,
            })

        return row


# --------------------------------------------------------------------------- #
# Main processing
# --------------------------------------------------------------------------- #

def get_protocol_name(pkt) -> Optional[str]:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return None


def get_ip_layer(pkt):
    if pkt.haslayer(IP):
        return pkt[IP], False
    if pkt.haslayer(IPv6):
        return pkt[IPv6], True
    return None, False


class PcapProcessor:
    def __init__(self, metadata_loader: MetadataLoader):
        self.metadata_loader = metadata_loader

    def process_file(self, filepath: str, pcap_id: int) -> List[Dict[str, object]]:
        filename = os.path.basename(filepath)
        sample_hash, label = self.metadata_loader.lookup(filename)

        flows: Dict[FlowKey, FlowStats] = {}
        handshake_tracker = HandshakeTracker()

        packet_count = 0
        corrupted_count = 0

        try:
            reader = PcapReader(filepath)
        except Exception as exc:
            print(f"[ERROR] could not open {filename}: {exc}")
            return []

        with reader:
            for pkt in reader:
                packet_count += 1
                if packet_count % 20000 == 0:
                    print(f"    ...{filename}: {packet_count} packets processed")
                try:
                    self._process_packet(pkt, flows, handshake_tracker)
                except Exception:
                    corrupted_count += 1
                    continue

        print(f"  Finished {filename}: {packet_count} packets read, "
              f"{corrupted_count} skipped (unparseable), {len(flows)} flows found.")

        rows = []
        for flow_key, stats in flows.items():
            row = stats.finalize(handshake_tracker)
            row["pcap_id"] = pcap_id
            row["sample_hash"] = sample_hash
            row["label"] = label
            rows.append(row)
        return rows

    def _process_packet(self, pkt, flows: Dict[FlowKey, FlowStats], handshake_tracker: HandshakeTracker) -> None:
        ip_layer, is_v6 = get_ip_layer(pkt)
        if ip_layer is None:
            return  # non-IP traffic (ARP, etc.) is out of scope for flow features

        protocol = get_protocol_name(pkt)
        if protocol is None:
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        sport = 0
        dport = 0
        tcp_flags = None
        payload_bytes = b""

        if protocol == "TCP":
            tcp_layer = pkt[TCP]
            sport = int(tcp_layer.sport)
            dport = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
            if pkt.haslayer(Raw):
                payload_bytes = bytes(pkt[Raw].load)
        elif protocol == "UDP":
            udp_layer = pkt[UDP]
            sport = int(udp_layer.sport)
            dport = int(udp_layer.dport)
            if pkt.haslayer(Raw):
                payload_bytes = bytes(pkt[Raw].load)

        flow_key: FlowKey = (src_ip, dst_ip, sport, dport, protocol)
        ts = float(pkt.time)
        length = len(bytes(pkt))

        if flow_key not in flows:
            flows[flow_key] = FlowStats(flow_key)
            if protocol == "TCP":
                flows[flow_key].conn_key = canonical_connection_key(src_ip, dst_ip, sport, dport, protocol)

        flow = flows[flow_key]
        flow.add_packet(ts, length)

        if protocol == "TCP" and tcp_flags is not None and flow.conn_key is not None:
            handshake_tracker.observe(flow.conn_key, tcp_flags, False)

        # --- TLS ClientHello detection ---
        if protocol == "TCP" and payload_bytes[:1] == b"\x16":
            info = parse_tls_client_hello(payload_bytes)
            if info is not None:
                flow.maybe_set_tls(info)

        # --- HTTP request detection ---
        if protocol == "TCP" and payload_bytes and HTTP_METHOD_RE.match(payload_bytes):
            host_match = HTTP_HOST_RE.search(payload_bytes)
            host = host_match.group(1).decode("utf-8", errors="ignore").strip() if host_match else None
            flow.add_http_request(host)

        # --- DNS detection ---
        if pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            try:
                if dns_layer.qr == 0 and dns_layer.qd is not None:
                    qd = dns_layer.qd
                    # scapy chains multiple questions via qd/qd.payload
                    count = int(dns_layer.qdcount) if dns_layer.qdcount else 1
                    node = qd
                    for _ in range(max(count, 1)):
                        if node is None:
                            break
                        qname = getattr(node, "qname", None)
                        if qname:
                            if isinstance(qname, bytes):
                                qname = qname.decode("utf-8", errors="ignore")
                            flow.add_dns(qname.rstrip("."))
                        node = getattr(node, "payload", None)
                        if node is not None and node.__class__.__name__ != "DNSQR":
                            break
            except Exception:
                pass

    def process_directory(self, input_dir: str) -> List[Dict[str, object]]:
        patterns = [os.path.join(input_dir, "*.pcap"), os.path.join(input_dir, "*.pcapng")]
        files = sorted({f for pattern in patterns for f in glob.glob(pattern)})

        if not files:
            print(f"[WARN] no .pcap/.pcapng files found in {input_dir}")
            return []

        all_rows: List[Dict[str, object]] = []
        for pcap_id, filepath in enumerate(files, start=1):
            print(f"[{pcap_id}/{len(files)}] Processing {os.path.basename(filepath)} ...")
            rows = self.process_file(filepath, pcap_id)
            all_rows.extend(rows)
        return all_rows


# --------------------------------------------------------------------------- #
# CSV writing & summary
# --------------------------------------------------------------------------- #

def write_csv(rows: List[Dict[str, object]], output_path: str) -> None:
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            complete_row = {k: row.get(k, "") for k in CSV_FIELDNAMES}
            writer.writerow(complete_row)


def print_summary(rows: List[Dict[str, object]]) -> None:
    total_flows = len(rows)
    ja4_values = [r["ja4_fingerprint"] for r in rows if r.get("ja4_fingerprint")]
    unique_ja4 = len(set(ja4_values))
    top_ja4 = Counter(ja4_values).most_common(20)
    labels = Counter(r.get("label", "unknown") for r in rows)

    print("\n" + "=" * 60)
    print("DATASET SUMMARY")
    print("=" * 60)
    print(f"Total flows extracted: {total_flows}")
    print(f"Unique JA4 fingerprints: {unique_ja4}")
    print("\nTop 20 most common JA4 fingerprints:")
    if top_ja4:
        for fp, count in top_ja4:
            print(f"  {count:6d}  {fp}")
    else:
        print("  (no TLS flows found)")
    print("\nFlows per label:")
    for label, count in labels.most_common():
        print(f"  {label}: {count}")
    print("=" * 60)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a flow-level JA4/JA3 malware traffic dataset from a directory of PCAPs."
    )
    parser.add_argument("--input-dir", required=True, help="Directory containing .pcap/.pcapng files")
    parser.add_argument("--metadata", required=True, help="Path to metadata.txt (pcap_file,sample_hash,label)")
    parser.add_argument("--output", default="dataset.csv", help="Output CSV path (default: dataset.csv)")
    args = parser.parse_args()

    metadata_loader = MetadataLoader(args.metadata)
    processor = PcapProcessor(metadata_loader)

    rows = processor.process_directory(args.input_dir)

    write_csv(rows, args.output)
    print(f"\nSaved {len(rows)} flow rows to {args.output}")

    print_summary(rows)


if __name__ == "__main__":
    main()