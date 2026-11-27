#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
       Castle Anti-Bot Unencrypted Field & Token Generator (V1 / V2 / V3)
=============================================================================
 Bộ sinh (Generator) cho các field chưa mã hoá (human-readable / plaintext)
 và bộ mã hoá hoàn chỉnh (Encoder) tạo Castle Token hợp lệ cho cả 3 phiên bản:
   - V1 (uq1seNrd) : 749 metrics (dựa trên castle.umd-B6QTm2FJ.js & scope_extracted.json)
   - V2 (cNz8rPYH) : 768 metrics (lr() string cipher + kd() Float32 timing + FNV-1a V2)
   - V3 (WcmFKZlD) : 772 metrics (Gn()/Kn() string cipher + Qd() Float32 timing + FNV-1a V3)

 Kiến trúc Pipeline:
   1. Unencrypted Field Generator:
      Sinh toàn bộ mảng metrics ở dạng chưa mã hoá (plaintext / human-readable)
      từ ClientProfile (OS, Browser,UA, GPU, Screen, Network, Anti-Bot flags,
      Timing probes...) hoặc nạp từ JSON đã decode và ghi đè (override) theo
      tên field (slug) hoặc chỉ số index.
   2. Per-Field Cipher Engine:
      - V1: Pn() / Mn() string cipher, On() int32 cipher, Fd() Float32 cipher,
            En()/Dn() cross-metric self-consistency hashes (658..667),
            cùng 54+ unencrypted/direct fields giữ nguyên theo AST gốc.
      - V2: lr() string cipher (ROL1 + ADD 0xC481 + ROL2 -> Base64),
            kd() Float32 timing cipher (683..767), giữ nguyên các field chưa mã hoá.
      - V3: Gn() string cipher (SUB 0xB1E6 -> XOR 0x72DC -> ROL4 -> Base64),
            Kn() string cipher (ADD 0x3F95 -> XOR 0x406F -> Base64),
            Qd() Float32 timing cipher (687..771), giữ nguyên các field chưa mã hoá.
   3. Binary Protocol Serializer (LEB128 varint + 11 kiểu dữ liệu) & Raw Deflate.
   4. 24-Byte Security Header (seg1 + seg2 + 16-byte checksum từ cipher_func.js)
      & Symmetric Stream Cipher (FNV-1a + Xorshift32 V1/V2/V3).
=============================================================================
"""

import os
import re
import sys
import json
import math
import time
import uuid
import zlib
import base64
import struct
import random
import socket
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Union

from decode_token import (
    METRIC_LABELS,
    METRIC_INFO_V2,
    METRIC_INFO_V3,
    METRIC_INFO_V4,
    PureCastleDecoder,
)

# Đảm bảo hỗ trợ UTF-8 trên Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ===========================================================================
# 1. CÁC HÀM MÃ HOÁ CẤP TRƯỜNG (PER-FIELD CIPHERS: FORWARD & INVERSE)
# ===========================================================================

def _u32(val: int) -> int:
    return val & 0xFFFFFFFF


def _i32(val: int) -> int:
    val = val & 0xFFFFFFFF
    return val - 0x100000000 if val >= 0x80000000 else val


def _imul(a: int, b: int) -> int:
    return ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & 0xFFFFFFFF


def _rol32(val: int, shift: int) -> int:
    val &= 0xFFFFFFFF
    shift &= 31
    return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF


def _ror32(val: int, shift: int) -> int:
    val &= 0xFFFFFFFF
    shift &= 31
    return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF


def encode_pn(text: str) -> str:
    """
    V1 Pn() String & Timestamp Key Encoder (castle.umd-B6QTm2FJ.js):
      e = (code << 15 | code >> 1) & 0xFFFF
      e = (e << 10 | e >> 6) & 0xFFFF
      e = (e + 6396) & 0xFFFF
      Big-endian uint16 -> Base64
    """
    out = bytearray()
    for ch in text:
        e = ord(ch) & 0xFFFF
        e = ((e << 15) | (e >> 1)) & 0xFFFF
        e = ((e << 10) | (e >> 6)) & 0xFFFF
        e = (e + 6396) & 0xFFFF
        out.append((e >> 8) & 0xFF)
        out.append(e & 0xFF)
    return base64.b64encode(bytes(out)).decode("ascii")


def encode_mn(text: str) -> str:
    """
    V1 Mn() String Encoder (scope_extracted.json):
      e = ROR2(code)
      e = (e - 0xBCA8 - 0x4CBB) & 0xFFFF
      e = (imul(e, 0x09B7) + 0x0EB5 + 0xF222) & 0xFFFF
      e = ROL1(e)
      Big-endian uint16 -> Base64
    """
    out = bytearray()
    for ch in text:
        e = ord(ch) & 0xFFFF
        e = ((e >> 2) | (e << 14)) & 0xFFFF
        e = (e - 0xBCA8) & 0xFFFF
        e = (e - 0x4CBB) & 0xFFFF
        e = ((e * 0x09B7) + 0x0EB5) & 0xFFFF
        e = (e + 0xF222) & 0xFFFF
        e = ((e << 1) | (e >> 15)) & 0xFFFF
        out.append((e >> 8) & 0xFF)
        out.append(e & 0xFF)
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_mn(b64_str: str) -> str:
    """Hàm giải mã ngược của V1 Mn() (sử dụng nghịch đảo modular 0x09B7^-1 = 0x8DF7 mod 65536)."""
    padded = b64_str + "=" * (-len(b64_str) % 4)
    raw = base64.b64decode(padded)
    chars = []
    for i in range(0, len(raw), 2):
        if i + 1 < len(raw):
            e = (raw[i] << 8) | raw[i + 1]
            e = ((e >> 1) | (e << 15)) & 0xFFFF
            e = (e - 0xF222 - 0x0EB5) & 0xFFFF
            e = (e * 0x8DF7) & 0xFFFF  # 0x09B7 * 0x8DF7 === 1 (mod 65536)
            e = (e + 0x4CBB + 0xBCA8) & 0xFFFF
            e = ((e << 2) | (e >> 14)) & 0xFFFF
            chars.append(chr(e))
    return "".join(chars)


def encode_on(val: int) -> int:
    """
    V1 On() 32-bit Integer Encoder (scope_extracted.json):
      e = (val - 0xFFFFFCC7 + 69) & 0xFFFFFFFF
      e = ROR32(e, 9)
      e = ROL32(e, 11)
      Trả về int32 có dấu (như toán tử bitwise & trong JS).
    """
    e = val & 0xFFFFFFFF
    e = (e - 0xFFFFFCC7) & 0xFFFFFFFF
    e = (e + 69) & 0xFFFFFFFF
    e = _ror32(e, 9)
    e = _rol32(e, 11)
    return _i32(e)


def decode_on(val: int) -> int:
    """Hàm giải mã ngược của V1 On()."""
    e = val & 0xFFFFFFFF
    e = _ror32(e, 11)
    e = _rol32(e, 9)
    e = (e - 69 + 0xFFFFFCC7) & 0xFFFFFFFF
    return _i32(e)


def encode_lr(text: str) -> str:
    """
    V2 lr() String & Timestamp Key Encoder:
      v = ROL1(code)
      v = (v + 0xC481) & 0xFFFF
      v = ROL2(v)
      Big-endian uint16 -> Base64
    """
    out = bytearray()
    for ch in text:
        v = ord(ch) & 0xFFFF
        v = ((v << 1) | (v >> 15)) & 0xFFFF
        v = (v + 0xC481) & 0xFFFF
        v = ((v << 2) | (v >> 14)) & 0xFFFF
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
    return base64.b64encode(bytes(out)).decode("ascii")


def encode_gn(text: str) -> str:
    """
    V3 Gn() String & Timestamp Key Encoder (WcmFKZlD):
      v = (code - 0xB1E6) & 0xFFFF
      v = (v ^ 0x72DC) & 0xFFFF
      v = ROL4(v)
      Big-endian uint16 -> Base64
    """
    out = bytearray()
    for ch in text:
        v = ord(ch) & 0xFFFF
        v = (v - 0xB1E6) & 0xFFFF
        v = (v ^ 0x72DC) & 0xFFFF
        v = ((v << 4) | (v >> 12)) & 0xFFFF
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_gn(b64_str: str) -> Optional[str]:
    """Hàm giải mã ngược của V3 Gn()."""
    if not isinstance(b64_str, str) or len(b64_str) < 4:
        return None
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        raw = base64.b64decode(padded)
        if len(raw) < 2 or len(raw) % 2 != 0:
            return None
        chars = []
        for i in range(0, len(raw), 2):
            v = (raw[i] << 8) | raw[i + 1]
            v = ((v >> 4) | (v << 12)) & 0xFFFF
            v = (v ^ 0x72DC) & 0xFFFF
            v = (v + 0xB1E6) & 0xFFFF
            chars.append(chr(v))
        return "".join(chars)
    except Exception:
        return None


def encode_kn(text: str) -> str:
    """
    V3 Kn() Secondary String Encoder (WcmFKZlD):
      v = ((code + 0x3F95) & 0xFFFF) ^ 0x406F
      Big-endian uint16 -> Base64
    """
    out = bytearray()
    for ch in text:
        v = ord(ch) & 0xFFFF
        v = ((v + 0x3F95) & 0xFFFF) ^ 0x406F
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
    return base64.b64encode(bytes(out)).decode("ascii")


def encode_nr(text: str) -> str:
    """
    V4 nr() String & Timestamp Key Encoder (EZK-f_Qb):
      v = (code ^ 0x2042) & 0xFFFF
      v = (v + 0x486D) & 0xFFFF
      v = ROR5(v)
      Big-endian uint16 -> Base64
    """
    out = bytearray()
    for ch in text:
        v = (ord(ch) ^ 0x2042) & 0xFFFF
        v = (v + 0x486D) & 0xFFFF
        v = ((v >> 5) | (v << 11)) & 0xFFFF
        out.append((v >> 8) & 0xFF)
        out.append(v & 0xFF)
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_nr(b64_str: str) -> Optional[str]:
    """Hàm giải mã ngược của V4 nr()."""
    if not isinstance(b64_str, str) or len(b64_str) < 4:
        return None
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        raw = base64.b64decode(padded)
        if len(raw) < 2 or len(raw) % 2 != 0:
            return None
        chars = []
        for i in range(0, len(raw), 2):
            val = (raw[i] << 8) | raw[i + 1]
            val = ((val << 5) | (val >> 11)) & 0xFFFF
            val = (val - 0x486D) & 0xFFFF
            val = (val ^ 0x2042) & 0xFFFF
            chars.append(chr(val))
        return "".join(chars)
    except Exception:
        return None


def encode_wd_float32(val: float) -> str:
    """
    V4 Wd() 4-byte Float32 Timing Probe Encoder (indices 691..775):
      Inverse của _wd_decode_float32:
      r = ROL8(r, 1)
      r = (r + 118) & 0xFF
      r = ROL8(r, 5)
    """
    raw = struct.pack(">f", float(val))
    out = bytearray(4)
    for i in range(4):
        r = raw[i]
        r = ((r << 1) | (r >> 7)) & 0xFF
        r = (r + 118) & 0xFF
        r = ((r << 5) | (r >> 3)) & 0xFF
        out[i] = r
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_wd_float32_exact(b64_str: str) -> Optional[float]:
    """Giải mã ngược V4 Wd() Float32 giữ nguyên độ chính xác IEEE-754 float32."""
    if not isinstance(b64_str, str) or len(b64_str) < 4:
        return None
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        raw = base64.b64decode(padded)
        if len(raw) != 4:
            return None
        out = bytearray(4)
        for i in range(4):
            r = raw[i]
            r = ((r >> 5) | (r << 3)) & 0xFF
            r = (r - 118) & 0xFF
            r = ((r >> 1) | (r << 7)) & 0xFF
            out[i] = r
        return struct.unpack(">f", bytes(out))[0]
    except Exception:
        return None


def decode_kn(b64_str: str) -> Optional[str]:
    """Hàm giải mã ngược của V3 Kn()."""
    if not isinstance(b64_str, str) or len(b64_str) < 4:
        return None
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        raw = base64.b64decode(padded)
        if len(raw) < 2 or len(raw) % 2 != 0:
            return None
        chars = []
        for i in range(0, len(raw), 2):
            v = (raw[i] << 8) | raw[i + 1]
            v = ((v ^ 0x406F) - 0x3F95) & 0xFFFF
            chars.append(chr(v))
        return "".join(chars)
    except Exception:
        return None


def encode_v3_int_a(val: int) -> int:
    """
    V3 Group A 32-bit Integer Cipher (WcmFKZlD):
      ror2 = (312282 - 381 * val) & 0xFFFFFFFF
      encoded = _i32(_rol32(ror2, 2))
    """
    ror2 = (312282 - _imul(381, val)) & 0xFFFFFFFF
    return _i32(_rol32(ror2, 2))


def decode_v3_int_a(val: int) -> Optional[int]:
    """Hàm giải mã ngược của V3 Group A Integer Cipher."""
    if not isinstance(val, int) or isinstance(val, bool):
        return None
    rv = _ror32(val & 0xFFFFFFFF, 2)
    diff = _i32((312282 - rv) & 0xFFFFFFFF)
    if diff % 381 == 0:
        x = diff // 381
        if -100000 <= x <= 10000000:
            return x
    return None


def encode_v3_int_b(val: int) -> int:
    """
    V3 Group B 32-bit Integer Cipher (WcmFKZlD, 49207 / 49367 family):
      encoded = ((6150 + val) << 3) | 7
    """
    return _i32((((6150 + val) & 0x1FFFFFFF) << 3) | 7)


def decode_v3_int_b(val: int) -> Optional[int]:
    """Hàm giải mã ngược của V3 Group B Integer Cipher."""
    if not isinstance(val, int) or isinstance(val, bool):
        return None
    if (val & 7) == 7:
        k = (val >> 3) - 6150
        if -1000 <= k <= 1000:
            return k
    return None


def encode_fd_float32(val: float) -> str:
    """
    V1 Fd() 4-byte Float32 Timing Probe Encoder (indices 668..748):
      b = (b + 133) & 0xFF
      b = (b * 123) & 0xFF
      b = (b ^ 177) & 0xFF
      b = ROL8(b, 3)
    """
    raw = struct.pack(">f", float(val))
    out = bytearray(4)
    for i in range(4):
        b = (raw[i] + 133) & 0xFF
        b = (b * 123) & 0xFF
        b = (b ^ 177) & 0xFF
        b = ((b << 3) | (b >> 5)) & 0xFF
        out[i] = b
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_fd_float32(b64_str: str) -> Optional[float]:
    """Hàm giải mã ngược của V1 Fd() Float32 (123 * 19 === 1 mod 256)."""
    if not isinstance(b64_str, str) or len(b64_str) < 4:
        return None
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        raw = base64.b64decode(padded)
        if len(raw) != 4:
            return None
        out = bytearray(4)
        for i in range(4):
            b = ((raw[i] >> 3) | (raw[i] << 5)) & 0xFF
            b = (b ^ 177) & 0xFF
            b = (b * 19) & 0xFF
            b = (b - 133) & 0xFF
            out[i] = b
        val = struct.unpack(">f", bytes(out))[0]
        if -1e6 < val < 1e9:
            return round(val, 2)
    except Exception:
        pass
    return None


def encode_kd_float32(val: float) -> str:
    """
    V2 kd() 4-byte Float32 Timing Probe Encoder (indices 683..767):
      Inverse của _kd_decode_float32:
      b = ROL8(b, 6)
      b = (b ^ 0x8F) & 0xFF
      b = (b + 0x99) & 0xFF
    """
    raw = struct.pack(">f", float(val))
    out = bytearray(4)
    for i in range(4):
        b = ((raw[i] << 6) | (raw[i] >> 2)) & 0xFF
        b = (b ^ 0x8F) & 0xFF
        b = (b + 0x99) & 0xFF
        out[i] = b
    return base64.b64encode(bytes(out)).decode("ascii")


def encode_qd_float32(val: float) -> str:
    """
    V3 Qd() 4-byte Float32 Timing Probe Encoder (indices 687..771):
      Inverse của _qd_decode_float32 (15 * 239 === 1 mod 256):
      b = ROL8(b, 5)
      b = (b ^ 0x6F) & 0xFF
      b = (b * 239) & 0xFF
    """
    raw = struct.pack(">f", float(val))
    out = bytearray(4)
    for i in range(4):
        b = ((raw[i] << 5) | (raw[i] >> 3)) & 0xFF
        b = (b ^ 0x6F) & 0xFF
        b = (b * 239) & 0xFF
        out[i] = b
    return base64.b64encode(bytes(out)).decode("ascii")


def decode_qd_float32_exact(b64_str: str) -> Optional[float]:
    """Giải mã ngược V3 Qd() Float32 giữ nguyên độ chính xác IEEE-754 float32 (không làm tròn)."""
    if not isinstance(b64_str, str) or len(b64_str) < 4:
        return None
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        raw = base64.b64decode(padded)
        if len(raw) != 4:
            return None
        out = bytearray(4)
        for i in range(4):
            b = (raw[i] * 15) & 0xFF
            b = (b ^ 0x6F) & 0xFF
            b = ((b >> 5) | (b << 3)) & 0xFF
            out[i] = b
        return struct.unpack(">f", bytes(out))[0]
    except Exception:
        return None


def encode_v1_os_field(os_name: str = "Windows", arch: str = "x86", extra: str = "") -> str:
    """
    Đóng gói trường OS của V1 ($[59] / $[DT]) theo đúng định dạng nhị phân của Castle JS:
      chr(3) + chr(len(os_name)) + chr(len(arch)) + chr(len(extra)) + os_name + arch + extra
      Ví dụ: 'Windows (x86_64)' -> '\\x03\\x07\\x03\\x00Windowsx86'
    """
    if os_name.startswith("\x03"):
        return os_name
    if "Windows" in os_name:
        os_part = "Windows"
        arch_part = "x86"
    elif "Mac" in os_name:
        os_part = "Macintosh"
        arch_part = "ARM" if "arm" in os_name.lower() else "Intel"
    elif "Linux" in os_name:
        os_part = "Linux"
        arch_part = "x86_64"
    else:
        os_part = os_name
        arch_part = arch
    return (
        chr(3)
        + chr(len(os_part) & 0x7F)
        + chr(len(arch_part) & 0x7F)
        + chr(len(extra) & 0x7F)
        + os_part
        + arch_part
        + extra
    )


def encode_v3_os_field(os_name: str = "Windows", arch: str = "x86", extra: str = "") -> str:
    """
    Đóng gói trường OS của V3 ($[53]) theo đúng định dạng nhị phân của Castle V3:
      chr(3) + chr(len(os_name)) + chr(len(extra)) + chr(len(arch)) + os_name + extra + arch
      Ví dụ: ('Windows', 'x86', '') -> '\\x03\\x07\\x00\\x03Windowsx86'
    """
    if os_name.startswith("\x03"):
        return os_name
    if "Windows" in os_name:
        os_part = "Windows"
        arch_part = arch or "x86"
    elif "Mac" in os_name:
        os_part = "Macintosh"
        arch_part = "ARM" if "arm" in os_name.lower() else (arch or "Intel")
    elif "Linux" in os_name:
        os_part = "Linux"
        arch_part = arch or "x86_64"
    else:
        os_part = os_name
        arch_part = arch
    return (
        chr(3)
        + chr(len(os_part) & 0x7F)
        + chr(len(extra) & 0x7F)
        + chr(len(arch_part) & 0x7F)
        + os_part
        + extra
        + arch_part
    )


def encode_v3_shader_field(shader_str: str = "w3c[][]e5f1648chlsl") -> str:
    """
    Đóng gói trường WebGL Shader Hash của V3 ($[78]) theo định dạng nhị phân:
      '\\x06\\x03\\x02\\x02\\x00\\x08\\x04w3c[][]e5f1648chlsl'
    """
    if shader_str.startswith("\x06"):
        return shader_str
    if shader_str.startswith("w3c[][]") and shader_str.endswith("hlsl") and len(shader_str) == 19:
        return "\x06\x03\x02\x02\x00\x08\x04" + shader_str
    return shader_str


def encode_v1_pair_or_int(
    val: Union[int, float],
    k1: int,
    m1: int,
    a1: int,
    x1: int,
    x2: int,
) -> Union[int, List[int]]:
    """
    Mã hoá số thực / số nguyên theo hàm băm cặp khả nghịch của Castle V1:
      - Nếu t = val * 1000 là số nguyên trong đoạn [0, 8191] và t / 1000 == val:
        trả về uint32: (imul(int(t) ^ k1, m1) + a1) >>> 0
      - Ngược lại:
        chuyển float64 sang 8 byte Big-Endian [hi_u32, lo_u32] rồi XOR với [x1, x2].
    """
    t = val * 1000
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        t_int = int(t) if math.isfinite(t) else -1
        if 0 <= t_int < 8192 and t_int == t and (t_int / 1000.0) == float(val):
            return (_imul(t_int ^ k1, m1) + a1) & 0xFFFFFFFF
    raw8 = struct.pack(">d", float(val))
    hi, lo = struct.unpack(">II", raw8)
    return [(hi ^ x1) & 0xFFFFFFFF, (lo ^ x2) & 0xFFFFFFFF]


def decode_v1_pair_or_int(
    encoded: Union[int, List[int]],
    k1: int,
    m1: int,
    a1: int,
    x1: int,
    x2: int,
) -> Optional[float]:
    """Giải mã ngược hàm băm cặp / affine của Castle V1 về giá trị float/int chưa mã hoá."""
    if isinstance(encoded, list) and len(encoded) == 2:
        hi = (int(encoded[0]) ^ x1) & 0xFFFFFFFF
        lo = (int(encoded[1]) ^ x2) & 0xFFFFFFFF
        raw8 = struct.pack(">II", hi, lo)
        return struct.unpack(">d", raw8)[0]
    if isinstance(encoded, int) and (m1 & 1) == 1:
        inv_m1 = pow(m1 & 0xFFFFFFFF, -1, 0x100000000)
        n = (_imul((encoded - a1) & 0xFFFFFFFF, inv_m1) ^ k1) & 0xFFFFFFFF
        if 0 <= n < 8192:
            return n / 1000.0 if (n % 1000) != 0 else float(n // 1000)
    return None


# ===========================================================================
# 2. HÀM BĂM TỰ KIỂM TRA CHÉO V1 En() & Dn() (INDICES 658..667)
# ===========================================================================

def hash_en(s: str) -> int:
    """
    Bản cài đặt Pure Python chính xác 100% của hàm băm En(e) trong castle.umd-B6QTm2FJ.js.
    Dùng để tính các trường tự kiểm tra chéo (cross-metric integrity) 658, 659, 661, 663, 664, 666, 667.
    """
    t0 = 0
    t1 = s
    length = len(t1) & 0xFFFFFFFF
    t2 = (0x07064442 ^ length) & 0xFFFFFFFF
    t2 = (t2 + (((t2 & 0xFFFF) << 13) | ((t2 & 0xFFFF) >> 19))) & 0xFFFFFFFF
    t3 = 0
    t2 = (_imul((t2 ^ (t2 >> 11)), 0xF92D9AC7) + 0x2CDA197A) & 0xFFFFFFFF
    t2 = (t2 ^ _imul(length, 0x084361B3)) & 0xFFFFFFFF
    t2 = _rol32(t2, 9)
    t2 = (t2 ^ _imul(t3, 0x18E269B9)) & 0xFFFFFFFF

    for t3 in range(len(t1)):
        t4 = ord(t1[t3]) & 0xFFFF
        t2 = (t2 ^ (t2 >> 17)) & 0xFFFFFFFF
        t2 = _rol32(t2, 16)
        t2 = (t2 ^ 0xAEF5C4C4) & 0xFFFFFFFF
        t2 = (_imul(t2 ^ t4, 0xFFADBF37) + 0x1ED0932A) & 0xFFFFFFFF
        t2 = (t2 ^ (t2 >> 11)) & 0xFFFFFFFF
        t2 = _imul(t2 ^ t4, 0x506EE54D)
        t2 = (t2 + (((t4 & 0xFFFF) << 11) | ((t4 & 0xFFFF) >> 21))) & 0xFFFFFFFF
        t2 = _imul(t2 ^ t4, 0x65153F95)
        t2 = (t2 ^ 0x5122DE98) & 0xFFFFFFFF
        t2 = (
            (t2 >> 24)
            | ((t2 >> 8) & 0xFF00)
            | ((t2 << 8) & 0xFF0000)
            | ((t2 << 24) & 0xFF000000)
        ) & 0xFFFFFFFF
        t2 = (t2 ^ _imul(length, 0x2183EB33)) & 0xFFFFFFFF
        t2 = _rol32(t2, 10)
        t2 = (t2 ^ _rol32(t0, 29)) & 0xFFFFFFFF
        t2 = (t2 + _imul(t4, 0xECA104CF)) & 0xFFFFFFFF
        t0 = (t0 + _imul(t4, 0x9E3779B1)) & 0xFFFFFFFF
        if (t3 & 3) == 3:
            t2 = (t2 ^ (((t2 & 0xFFFF) << 7) | ((t2 & 0xFFFF) >> 25))) & 0xFFFFFFFF
            t2 = (
                (t2 >> 24)
                | ((t2 >> 8) & 0xFF00)
                | ((t2 << 8) & 0xFF0000)
                | ((t2 << 24) & 0xFF000000)
            ) & 0xFFFFFFFF
            t2 = (_imul(t2 ^ (t2 >> 11), 0x47C2C183) + 0x6037F906) & 0xFFFFFFFF
            t2 = (t2 ^ (t2 >> 11)) & 0xFFFFFFFF
            t2 = (t2 ^ (((t2 & 0xFFFF) << 18) | ((t2 & 0xFFFF) >> 14))) & 0xFFFFFFFF

    t2 = (t2 ^ t0) & 0xFFFFFFFF
    t2 = (t2 + _imul(t0, 0x86361393)) & 0xFFFFFFFF
    t2 = (t2 ^ _rol32(t0, 3)) & 0xFFFFFFFF
    t2 = (t2 ^ t0) & 0xFFFFFFFF
    t2 = (t2 ^ _rol32(t0, 23)) & 0xFFFFFFFF
    t2 = (t2 ^ t0) & 0xFFFFFFFF
    t2 ^= t2 >> 16
    t2 = _imul(t2, 0x85EBCA6B)
    t2 ^= t2 >> 13
    t2 = _imul(t2, 0xC2B2AE35)
    t2 ^= t2 >> 16
    return t2 & 0xFFFFFFFF


def hash_dn(s: str) -> str:
    """
    Bản cài đặt Pure Python chính xác 100% của hàm băm Dn(e) trong castle.umd-B6QTm2FJ.js.
    Trả về chuỗi hex 8 ký tự thường (dùng cho các trường 660, 662, 665).
    """
    t1 = 0
    t2 = s
    length = len(t2) & 0xFFFFFFFF
    t3 = (0x564E5049 ^ length) & 0xFFFFFFFF
    t3 = _imul(t3 ^ (t3 >> 11), 0x7C407857)
    t3 = (t3 ^ (t3 >> 11)) & 0xFFFFFFFF
    t3 = (t3 ^ 0x3DEE8B8B) & 0xFFFFFFFF

    for t0 in range(len(t2)):
        t4 = ord(t2[t0]) & 0xFFFF
        t3 = (_imul(t3 ^ t4, 0x353EE503) + 0x5D116079) & 0xFFFFFFFF
        t3 = (_imul(t3 ^ t4, 0x639A5AA7) + 0xA599B1CD) & 0xFFFFFFFF
        t3 = (t3 ^ 0xC0B3778F) & 0xFFFFFFFF
        t3 = (t3 ^ _imul(length, 0xF5A36CCB)) & 0xFFFFFFFF
        t3 = (t3 ^ _imul(t0, 0x7C4A8877)) & 0xFFFFFFFF
        t3 = (t3 + _imul(t4, 0x99677FAF)) & 0xFFFFFFFF
        t3 = _rol32(t3, 13)
        t3 = (t3 ^ (t3 >> 10)) & 0xFFFFFFFF
        t3 = (
            (t3 >> 24)
            | ((t3 >> 8) & 0xFF00)
            | ((t3 << 8) & 0xFF0000)
            | ((t3 << 24) & 0xFF000000)
        ) & 0xFFFFFFFF
        t3 = _imul(t3 ^ t4, 0xE03D1B1F)
        t1 = (t1 + _imul(t4, 0x9E3779B1)) & 0xFFFFFFFF
        if (t0 & 3) == 3:
            t3 = _rol32(t3, 31)
            t3 = (t3 + _imul(t3 ^ (t3 >> 11), 0x7273D87B)) & 0xFFFFFFFF
            t3 = (t3 ^ (t3 >> 17)) & 0xFFFFFFFF

    t0_end = len(t2)
    t3 = (t3 ^ t1) & 0xFFFFFFFF
    t3 = (_imul(t3 ^ t1, 0x2A0465B3) + 0x0D8F0969) & 0xFFFFFFFF
    t3 = (t3 ^ _imul(t0_end, 0xED20DDE7)) & 0xFFFFFFFF
    t3 = (t3 ^ 0x1240FE73) & 0xFFFFFFFF
    t3 ^= t3 >> 16
    t3 = _imul(t3, 0x85EBCA6B)
    t3 ^= t3 >> 13
    t3 = _imul(t3, 0xC2B2AE35)
    t3 ^= t3 >> 16
    return f"{t3 & 0xFFFFFFFF:08x}"


def apply_v1_self_consistency_hashes(metrics: List[Any]) -> None:
    """
    Tính toán và cập nhật 10 trường tự kiểm tra chéo (658..667) trong mảng $ của V1
    dựa trên giá trị hiện tại của các trường nguồn (72, 131, 169, 269, 286, 325, 352, 398, 444, 540).
    """
    if len(metrics) < 668:
        return

    def _json_str(idx: int) -> str:
        val = metrics[idx]
        return json.dumps(val, separators=(",", ":"))

    # $[658] = Fee((En(JSON.stringify($[72])) >>> 8) & 0xFFFFFF) -> + 43
    metrics[658] = (((hash_en(_json_str(72)) >> 8) & 0xFFFFFF) + 43) & 0xFFFFFFFF
    # $[659] = Pee(En(JSON.stringify($[131])) & 0xFFFFFF) -> + 59
    metrics[659] = ((hash_en(_json_str(131)) & 0xFFFFFF) + 59) & 0xFFFFFFFF
    # $[660] = Pn(Dn(JSON.stringify($[169])).slice(3, 5))
    metrics[660] = encode_pn(hash_dn(_json_str(169))[3:5])
    # $[661] = Nee((En(JSON.stringify($[269])) >>> 16) & 0xFFFF) -> + 10
    metrics[661] = (((hash_en(_json_str(269)) >> 16) & 0xFFFF) + 10) & 0xFFFFFFFF
    # $[662] = Pn(Dn(JSON.stringify($[286])))
    metrics[662] = encode_pn(hash_dn(_json_str(286)))
    # $[663] = Mee(En(JSON.stringify($[325])) & 0xFFFFFF) -> + 63
    metrics[663] = ((hash_en(_json_str(325)) & 0xFFFFFF) + 63) & 0xFFFFFFFF
    # $[664] = jee(En(JSON.stringify($[352])) & 0xFFFFFF) -> + 36
    metrics[664] = ((hash_en(_json_str(352)) & 0xFFFFFF) + 36) & 0xFFFFFFFF
    # $[665] = Pn(Dn(JSON.stringify($[398])).slice(3, 6))
    metrics[665] = encode_pn(hash_dn(_json_str(398))[3:6])
    # $[666] = On(En(JSON.stringify($[444])) | 0)
    metrics[666] = encode_on(hash_en(_json_str(444)))
    # $[667] = Aee(En(JSON.stringify($[540])) & 0xFFFF) -> + 5
    metrics[667] = ((hash_en(_json_str(540)) & 0xFFFF) + 5) & 0xFFFFFFFF


# ===========================================================================
# 3. BINARY PROTOCOL SERIALIZER & STREAM CIPHER + 24-BYTE SECURITY HEADER
# ===========================================================================

def encode_varint(val: int) -> bytearray:
    """Mã hoá số nguyên không dấu 32-bit theo chuẩn LEB128 varint."""
    res = bytearray()
    val = val & 0xFFFFFFFF
    while val >= 128:
        res.append((val & 127) | 128)
        val >>= 7
    res.append(val & 127)
    return res


_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)


def is_valid_base64_blob(s: str) -> bool:
    """
    Kiểm tra chuỗi có phải Base64 hợp lệ (như hàm kiểm tra Type 2 trong castle.umd-B6QTm2FJ.js):
      typeof e === 'string' && e.length % 4 === 0 && regex.test(e) && btoa(atob(e)) === e
    """
    if not isinstance(s, str) or len(s) % 4 != 0 or not s:
        return False
    if not _BASE64_RE.match(s):
        return False
    try:
        decoded = base64.b64decode(s)
        return base64.b64encode(decoded).decode("ascii") == s
    except Exception:
        return False


def serialize_item(item: Any, out: bytearray) -> None:
    """Tuần tự hoá 1 phần tử trong mảng $ sang luồng byte theo Castle Binary Protocol (11 tags)."""
    if item is None:
        out.append(0)
    elif isinstance(item, bool):
        out.append(6 if item else 5)
    elif isinstance(item, str):
        if item == "" or is_valid_base64_blob(item):
            # Tag 2: Raw binary (từ Base64, kể cả chuỗi rỗng "" như btoa(atob("")) === "" trong Castle JS)
            raw = base64.b64decode(item) if item else b""
            out.append(2)
            out.extend(encode_varint(len(raw)))
            out.extend(raw)
        elif all(ord(c) <= 255 for c in item):
            # Tag 9: Latin-1 / ASCII string
            out.append(9)
            out.extend(encode_varint(len(item)))
            out.extend(item.encode("latin1"))
        else:
            # Tag 1: UTF-16LE string
            out.append(1)
            out.extend(encode_varint(len(item)))
            for c in item:
                code = ord(c) & 0xFFFF
                out.append(code & 0xFF)
                out.append((code >> 8) & 0xFF)
    elif isinstance(item, (int, float)):
        if math.isnan(item) or math.isinf(item):
            out.append(0)
            return
        if isinstance(item, int) or (isinstance(item, float) and item.is_integer()):
            val = int(item)
            if -2147483648 <= val <= 2147483647:
                # Tag 10: Zigzag varint ((e << 1) ^ (e >> 31)) >>> 0
                out.append(10)
                val32 = val & 0xFFFFFFFF
                signed_val = val if val < 0x80000000 else val - 0x100000000
                zz = ((val32 << 1) ^ (signed_val >> 31)) & 0xFFFFFFFF
                out.extend(encode_varint(zz))
            elif 0 <= val <= 0xFFFFFFFF:
                # Tag 3: uint32 Little-Endian
                out.append(3)
                out.extend(struct.pack("<I", val))
            else:
                # Tag 4: float64 Big-Endian
                out.append(4)
                out.extend(struct.pack(">d", float(item)))
        else:
            # Tag 4: float64 Big-Endian
            out.append(4)
            out.extend(struct.pack(">d", float(item)))
    elif isinstance(item, list):
        # Tag 7: Array
        out.append(7)
        out.extend(encode_varint(len(item)))
        for sub in item:
            serialize_item(sub, out)
    else:
        # Tag 8: JSON string (UTF-16LE)
        s = json.dumps(item, separators=(",", ":"), ensure_ascii=False)
        out.append(8)
        out.extend(encode_varint(len(s)))
        for c in s:
            code = ord(c) & 0xFFFF
            out.append(code & 0xFF)
            out.append((code >> 8) & 0xFF)


def serialize_castle_payload(metrics: List[Any]) -> bytes:
    """Tuần tự hoá toàn bộ mảng metrics ($) sang bytes."""
    out = bytearray()
    out.extend(encode_varint(len(metrics)))
    for item in metrics:
        serialize_item(item, out)
    return bytes(out)


def compress_castle_payload(serialized: bytes) -> bytes:
    """Nén dữ liệu đã serialize bằng Raw Deflate (wbits=-15, level=6 chuẩn pako/browser)."""
    compressor = zlib.compressobj(level=6, method=zlib.DEFLATED, wbits=-15)
    return compressor.compress(serialized) + compressor.flush()


def encrypt_with_security_header(
    compressed_bytes: bytes, key_str: str, version: int = 3
) -> bytes:
    """
    Thực thi hàm t[4] (cipher_func.js):
      1. Chia chiều dài payload nén thành 2 segment:
         seg1 = n3 - (n3 // 2), seg2 = n3 // 2 (8 byte đầu của header 24 byte).
      2. Tính FNV-1a 32-bit trên chuỗi timestamp 13 chữ số (key_str).
      3. Tính 4 từ 32-bit (16 byte) chữ ký toàn vẹn (checksum signature) trên toàn bộ
         dữ liệu nén và 2 segment (bytes 8..24 của header).
      4. Mã hoá luồng (Stream Cipher XOR) dữ liệu nén theo phiên bản V1, V2 hoặc V3.
      Trả về: 24-byte auth_header + ciphertext.
    """
    n3 = len(compressed_bytes)
    n6 = 0
    n7 = n3 // 2
    n8 = (n7 - n6) & 0xFFFFFFFF  # seg2
    n9 = n7
    n10 = n3
    n12 = (n10 - n9) & 0xFFFFFFFF  # seg1

    out = bytearray(24 + n3)
    # Ghi seg1 (4B BE) và seg2 (4B BE)
    out[0:4] = struct.pack(">I", n12)
    out[4:8] = struct.pack(">I", n8)

    # Tham số FNV-1a + Xorshift32 + 16-byte Checksum Signature theo phiên bản
    if version == 4:
        fnv_offset = 0xA72E5B0C
        c1, c2, c3 = 0x17113533, 0x48375C16, 0x0DDA1DEC
        seg2_xor1, seg_xor2 = 0x3B4091B7, 0x9AB81E61
        seg1_xor1 = 0x99191B64
        mask_seed_xor = 0xD389F06A
        glob_xor = 0xBE1BCF4B
        glob_add = 0xB7E64091
        seg_add, seg_xor = 0xB270070C, 0x072E62D5
        fin1_params = (0x0B56DEBB, 1, 0x4796C8DB, 0x6E1BBEDD)
        fin2_params = (0x4FCEFD99, 2, 0x0ACA3E2F, 0xD9E34E86)
        fin3_params = (0x9AB81E61, 3, 0xB270070D, 0x072E62D5)
        fin4_params = (0x9AB81E61, 5, 0xB270070D, 0x072E62D5)
    elif version == 3:
        fnv_offset = 0x4A391620
        c1, c2, c3 = 0x09007E08, 0x6F0FB60C, 0x391BF9C5
        seg2_xor1, seg_xor2 = 0x45B9AC9B, 0x8F60218D
        seg1_xor1 = 0xE7E02648
        mask_seed_xor = 0xBFB7740D
        glob_xor = 0x5FD4F9E0
        glob_add = 0xF7513302
        seg_add, seg_xor = 0x45D70BB1, 0x79D75FF9
        fin1_params = (0x36951111, 1, 0x3594AFFD, 0xBE0E52B1)
        fin2_params = (0xBE2270A8, 2, 0xE5BFC311, 0x5BBCADF0)
        fin3_params = (0x8F60218D, 3, 0x45D70BB1, 0x79D75FF9)
        fin4_params = (0x8F60218D, 5, 0x45D70BB1, 0x79D75FF9)
    elif version == 2:
        fnv_offset = 0x751DAC79
        c1, c2, c3 = 0x7F039DDA, 0x973D8749, 0x93CF09BD
        seg2_xor1, seg_xor2 = 0x760EABC8, 0x38C7C049
        seg1_xor1 = 0xD457211B
        mask_seed_xor = 0x310AAFFB
        glob_xor = 0xCD005044
        glob_add = 0x49713B7D
        seg_add, seg_xor = 0x02763A6C, 0x4A6058AA
        fin1_params = (0x92DC76DA, 1, 0x33CEC0C7, 0x54D0D0ED)
        fin2_params = (0x79076C2A, 2, 0x91E8D6EB, 0xDEFBDCC2)
        fin3_params = (0x38C7C049, 3, 0x02763A6D, 0x4A6058AA)
        fin4_params = (0x38C7C049, 5, 0x02763A6D, 0x4A6058AA)
    else:
        fnv_offset = 0xBC0D78D5
        c1, c2, c3 = 0x155FACDB, 0x989BDC08, 0xA4A5C55B
        seg2_xor1, seg_xor2 = 0x760EABC8, 0x38C7C049
        seg1_xor1 = 0xD457211B
        mask_seed_xor = 0x310AAFFB
        glob_xor = 0xCD005044
        glob_add = 0x49713B7D
        seg_add, seg_xor = 0x02763A6C, 0x4A6058AA
        fin1_params = (0x92DC76DA, 1, 0x33CEC0C7, 0x54D0D0ED)
        fin2_params = (0x79076C2A, 2, 0x91E8D6EB, 0xDEFBDCC2)
        fin3_params = (0x38C7C049, 3, 0x02763A6D, 0x4A6058AA)
        fin4_params = (0x38C7C049, 5, 0x02763A6D, 0x4A6058AA)

    # FNV-1a cho checksum header (theo cipher_func.js / castle.umd-CGiQ_kr0.js)
    n14 = fnv_offset
    for ch in key_str:
        n14 = _imul(n14 ^ ord(ch), 0x01000193)
    if n14 == 0:
        n14 = 0x9E3779B9

    n17 = (n14 ^ seg2_xor1 ^ seg_xor2) & 0xFFFFFFFF
    n18 = (n14 ^ mask_seed_xor) & 0xFFFFFFFF
    n19 = (n14 ^ seg1_xor1 ^ seg_xor2) & 0xFFFFFFFF
    n20 = (n14 ^ c2) & 0xFFFFFFFF
    n21 = (n14 ^ glob_xor) & 0xFFFFFFFF

    for i in range(n3):
        b = compressed_bytes[i] & 0xFF
        # Cập nhật accumulator toàn cục n21
        n21 = (
            n21 ^ ((b + ((i + glob_add) & 0xFF)) & 0xFFFFFFFF) ^ glob_xor
        ) & 0xFFFFFFFF
        n21 ^= n21 >> 13

        # Cập nhật accumulator cho segment 1 (n19) hoặc segment 2 (n17)
        if i < n7:
            n19 = (
                n19
                ^ ((b + ((i - n6 + seg_add) & 0xFF)) & 0xFFFFFFFF)
                ^ seg_xor
            ) & 0xFFFFFFFF
            n19 ^= n19 >> 13
        elif i < n10:
            n17 = (
                n17
                ^ ((b + ((i - n9 + seg_add) & 0xFF)) & 0xFFFFFFFF)
                ^ seg_xor
            ) & 0xFFFFFFFF
            n17 ^= n17 >> 13

        # Cập nhật trạng thái PRNG Xorshift32 mỗi 4 byte
        if (i & 3) == 0:
            n20 = (n20 + i + c1) & 0xFFFFFFFF
            n20 = (n20 + c2) & 0xFFFFFFFF
            n20 = (n20 ^ ((n20 << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            n20 = (n20 ^ (n20 >> 17)) & 0xFFFFFFFF
            n20 = (n20 ^ ((n20 << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            n20 = (n20 + c3) & 0xFFFFFFFF

        out[24 + i] = b ^ ((n20 >> ((i & 3) * 8)) & 0xFF)

    # Finalize 4 chữ ký 32-bit (n24, n25, n26, n44)
    def _finalize_word(acc: int, xor_init: int, step: int, mul1: int, dp_xor: int) -> int:
        w = (acc ^ xor_init ^ step) & 0xFFFFFFFF
        w = _imul(w ^ (w >> 16), mul1)
        w = (_rol32(w, 13) ^ dp_xor) & 0xFFFFFFFF
        w = _imul(w ^ (w >> 15), 0x01000193)
        return w

    def _mask_word(seed: int, step: int) -> int:
        m = _imul((seed ^ step ^ mask_seed_xor) & 0xFFFFFFFF, 0x01000193)
        m ^= m >> 16
        m = _imul(m, mask_seed_xor)
        return m

    n24 = _finalize_word(n21, *fin1_params)
    n25 = _finalize_word(n21, *fin2_params)
    n26 = _finalize_word(n19, *fin3_params)
    n44 = _finalize_word(n17, *fin4_params)

    n45 = _mask_word(n18, 0)
    n46 = _mask_word(n18, 1)
    n64 = _mask_word(n18, 2)
    n65 = _mask_word(n18, 3)

    struct.pack_into(">IIII", out, 8, n24 ^ n45, n25 ^ n46, n26 ^ n64, n44 ^ n65)
    return bytes(out)


# ===========================================================================
# 4. CẤU HÌNH PROFILE NGƯỜI DÙNG & TRÍCH XUẤT AST V1
# ===========================================================================

_CACHED_LOCAL_IP: Optional[str] = None
_CACHED_PUBLIC_IP: Optional[str] = None


def detect_local_ip() -> str:
    """Tự động lấy địa chỉ IP LAN của máy hiện tại qua UDP socket (không gửi gói tin)."""
    global _CACHED_LOCAL_IP
    if _CACHED_LOCAL_IP:
        return _CACHED_LOCAL_IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                _CACHED_LOCAL_IP = ip
                return ip
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip:
            _CACHED_LOCAL_IP = ip
            return ip
    except Exception:
        pass
    _CACHED_LOCAL_IP = "192.168.1.100"
    return _CACHED_LOCAL_IP


def detect_public_ip(timeout: float = 1.5) -> str:
    """
    Tự động lấy địa chỉ Public IP (WAN) của máy hiện tại (tương đương WebRTC srflx candidate).
    Nếu máy ngoại tuyến hoặc không kết nối được, tự động fallback về IP LAN của máy.
    """
    global _CACHED_PUBLIC_IP
    if _CACHED_PUBLIC_IP:
        return _CACHED_PUBLIC_IP
    endpoints = (
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://icanhazip.com",
    )
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode("utf-8", errors="ignore").strip()
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                    _CACHED_PUBLIC_IP = ip
                    return ip
        except Exception:
            continue
    _CACHED_PUBLIC_IP = detect_local_ip()
    return _CACHED_PUBLIC_IP


@dataclass
class ClientProfile:
    """
    Profile thiết bị & trình duyệt ở dạng chưa mã hoá (Human-Readable) dùng để
    sinh toàn bộ các field chưa mã hoá trong mảng metrics ($).
    Mặc định khớp 100% với mẫu V3 thực tế (Chrome 156 / Windows 10 / x.com) và tự động lấy IP thực.
    """
    # Định danh & Mạng (Tự động lấy theo IP máy hiện tại nếu không truyền vào)
    ip_address: str = field(default_factory=detect_public_ip)
    local_ip_fallback: str = "0.0.0.0"
    origin_url: str = "https://x.com"
    site_domain: str = "x.com"
    url_path: str = "/"
    page_title: str = "X. It’s what’s happening / X"
    protocol: str = "https:"
    webrtc_proto: str = "dtls-sctp+udp"
    webrtc_cand_type: str = "srflx"

    # Hệ điều hành & Phần cứng
    operating_system: str = "Windows"
    os_arch: str = "\x03\x07\x00\x03Windowsx86"
    platform: str = "Win32"
    platform_sub: str = "20030107"
    architecture: str = "x86"
    arch_bits: str = "64"
    hw_concurrency: int = 8
    device_memory: int = 8
    timezone: str = "Etc/GMT-7"
    tz_offset_raw: int = 121
    tz_offset_hex: str = "1a4"
    locale: str = "en-US"
    language: str = "en-US"
    accept_langs: str = "en-US,en"
    date_probe: str = "3/1/1970, 7:00:00 AM"
    storage_quota_est: int = 299982909440

    # Trình duyệt
    browser_name: str = "Google Chrome"
    browser_version: str = "156.0.8078.81"
    browser_ver_detail: str = "156.0.8078.81"
    browser_vendor: str = "Google Inc."
    render_engine: str = "webkit"
    engine_version: str = "10.0.0"
    build_id: str = "20030107"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
    )
    ua_brands: str = (
        '[{"brand":"Not:A-Brand","version":"8.0.0.0"},'
        '{"brand":"Chromium","version":"156.0.8078.81"},'
        '{"brand":"Google Chrome","version":"156.0.8078.81"}]'
    )
    ua_brands_short: str = (
        '[{"brand":"Not:A-Brand","version":"8"},'
        '{"brand":"Chromium","version":"156"},'
        '{"brand":"Google Chrome","version":"156"}]'
    )
    pdf_viewer_enabled: bool = True
    cookie_flag: bool = True
    history_length: int = 3
    visibility: str = "visible"
    nav_type: str = "navigate"
    last_event: str = "mousewheel"

    # Màn hình & Đồ hoạ (GPU / WebGL / Canvas / Audio)
    screen_width: int = 1920
    screen_height: int = 1080
    inner_width: int = 1663
    inner_height: int = 919
    color_depth: int = 24
    device_pixel_ratio: float = 1.0
    screen_orient: str = "landscape-primary"
    display_type: str = "screen"
    gpu_vendor: str = "nvidia"
    gpu_renderer: str = "ANGLE (NVIDIA, NVIDIA GeForce GT 710 (0x0000128B) Direct3D11 vs_5_0 ps_5_0, D3D11)"
    gpu_arch: str = "kepler"
    shader_hash_str: str = "\x06\x03\x02\x02\x00\x08\x04w3c[][]e5f1648chlsl"
    shader_source: str = (
        "// INITIAL HLSL BEGIN\n\n"
        "#pragma warning( disable: 3081 3556 3557 3571 )\n"
        "#ifdef ANGLE_ENABLE_LOOP_FLATTEN\n"
        "#define LOOP [lo"
    )
    canvas_hash: Union[str, int] = "bd4be70d"
    webgl_fp: Union[str, int] = "dffe8659"
    audio_hash: Union[str, int] = "cba5f63a"
    audio_sample_rate: int = 48000
    audio_max_channels: int = 2

    # Token & Phiên (Session)
    castle_pubkey: str = "pk_AvRa79bHyJSYSQHnRpcVtzyxetSvFerx"
    device_guid: str = "eb8011a2-5cfb-49c6-b123-b47b47359790"
    session_id: str = "35265rw7jc"
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    secondary_ts: Union[str, int] = field(default_factory=lambda: str(int(time.time() * 1000) - 1359197))

    # Cờ Anti-Bot & Probes (Mặc định: Người dùng thật - VERIFIED_GENUINE_HUMAN)
    webdriver_active: bool = False
    automation_detected: bool = False
    headless_detected: bool = False
    devtools_open: bool = False
    cdp_active: bool = False
    cdp_code: str = "N"
    selenium_cdc_flag: bool = False
    chrome_runtime_flag: bool = False
    chrome_obj_present: bool = True
    perf_memory_present: bool = True
    chrome_csi_present: bool = True
    window_prop_check: bool = True
    feature_support_flag: bool = True
    error_probe_type: str = "RangeError"
    error_probe_inv: str = "Illegal invocation"
    error_probe_prop: str = "Cannot read properties of undefined (reading 'b')"
    css_selector_fp: str = (
        "RAEAfwP7qoQ8AAP5Y9mWAAMXVKEWAAMHBTpyb290LwMJLnItMTJob3c5YgIxW2RhdGEtc29ubmVyLXRvYXN0ZXJd"
        "W2Rpcj0ibHRyIl0sIGh0bWxbZGlyPSJsdHIiXekCYRMuamV0ZnVlbC1zdHlsZS1yb290igbZBB0uamV0ZnVlbC1z"
        "dHlsZS1yb290IC5qbmZqOWpzMDK1AQYucUpUSE3jAVEAXgTJAgrUA6tBAk4yTexjBnRJYgAGdEliAAZ0SWIABnRJ"
        "YgAGdEliAAZ0SWIALA4rjQAGdEliAFV8HZ4BAACQD64OAQAAkA+uDinub1aNuoUDXuroMAHEjHIZAW0ezIkBxIxy"
        "GSMiAAQEb8mW/sjW2pB5x/gEbINEYQ=="
    )
    proto_probe: str = "TypeError: Cyclic __proto__ value"
    stack_probe: str = "Maximum call stack size exceeded"
    feature_flags_bin: str = "1111111111111111111111111111111111111000000000"
    zero_flags: str = "0000000000000000000000000000000000000000000"


# Các trường chưa mã hoá trực tiếp (Direct / Ternary / Unencrypted) trong V1
# được trích xuất chính xác từ castle.umd-B6QTm2FJ.js & scope_extracted.json:
# (clean_human_value, bot_or_alt_value, description)
V1_DIRECT_UNENCRYPTED_DEFAULTS: Dict[int, Tuple[Any, Any, str]] = {
    0: ("F", "l", "Brave browser check ($[T]: e ? 'l' : 'F')"),
    11: ("t", "xLp", "Prototype / Array constructor check ($[N])"),
    17: (14181, 57815, "Feature flag ternary ($[I]: e ? 57815 : 14181)"),
    19: (54998, 40536, "Permission/Environment check ($[lb]: LX(e) ? 40536 : 54998)"),
    20: ("Pj", "l", "Browser capability flag ($[SS]: IX() ? 'Pj' : 'l')"),
    22: (False, True, "WebDriver active flag ($[fb] = p(Np, PX(e)))"),
    44: (False, True, "Automation / Selenium / CDC detected ($[wb] = f(Wf, e))"),
    53: ("iCw", "iMRQ", "Constructor prototype tampering check ($[I_])"),
    54: ("xK", "OA", "Automation property check ($[Uy])"),
    55: (24661, 15729, "Environment consistency check ($[Q_]: UY() ? 15729 : 24661)"),
    63: (557, 34942, "Automation descriptor check ($[D_]: NY() ? 34942 : 557)"),
    70: (22772, 61154, "Canvas winding / environment check ($[qS]: EY() ? 61154 : 22772)"),
    80: ("m", "WCh", "Touch/Pointer state flag ($[Jy]: e ? 'WCh' : 'm')"),
    118: (57933, 9674, "Probe state ternary ($[sx]: e ? 9674 : 57933)"),
    131: (26901, 5441, "DOM element state ternary ($[Jb]: e ? 5441 : 26901)"),
    133: ("prcT", "t", "Headless / Function.prototype.toString check ($[ix]: Foe() ? 't' : 'prcT')"),
    143: (False, True, "Headless browser detected ($[Yx] = f(Mf, Toe()))"),
    148: (13297, 42281, "SmartTV / NetCast check ($[zv]: e ? 42281 : 13297)"),
    151: (False, True, "DevTools / Object.setPrototypeOf probe ($[hC] = d(Ff, e))"),
    155: (False, True, "Firefox Error.toSource probe ($[NS] = d(Ud, e))"),
    175: ("H", "SW", "ServiceWorker / Worker scope check ($[zy]: e ? 'SW' : 'H')"),
    202: ("yx", "YF", "Date.now native check ($[ax]: e ? 'YF' : 'yx')"),
    248: (True, False, "Navigator property check ($[Wy] = u(Bf, e))"),
    249: ("f", "e", "Event state flag ($[Ky]: e ? 'e' : 'f')"),
    313: (False, True, "ActiveXObject presence check ($[Qy] = f(Up, e))"),
    327: ("XnRd", "IS", "Automation / IE check ($[327]: e ? 'IS' : 'XnRd')"),
    348: (47096, 64609, "Screen / Window state ternary ($[Vv]: e ? 64609 : 47096)"),
    367: ("CwgC", "mei", "Platform sub check ($[Gy]: e ? 'mei' : 'CwgC')"),
    383: (False, True, "Chrome DevTools Protocol (CDP) active ($[yT])"),
    388: (49464, 44443, "Header / Security state ternary ($[By]: e ? 44443 : 49464)"),
    390: (52734, 37607, "Navigator / Security state ternary ($[Ry]: e ? 37607 : 52734)"),
    392: ("m", "gI", "Config state flag ($[jP]: e ? 'gI' : 'm')"),
    393: (10197, 62936, "DoNotTrack flag ($[YS]: n ? 62936 : 10197)"),
    457: (False, True, "Window special property check ($[Bv] = f(Hp, e))"),
    467: (False, True, "Touch points consistency check ($[467] = f(zp, e))"),
    479: (31065, 47490, "Context state ternary ($[wT]: e ? 47490 : 31065)"),
    485: ("gN", "caU", "Environment probe ($[485]: YJ() ? 'gN' : 'caU')"),
    490: ("fvEd", "ZowU", "Intl / Locale check ($[pI]: WJ() ? 'fvEd' : 'ZowU')"),
    492: ("VU", "c", "navigator.oscpu check ($[FS]: e ? 'c' : 'VU')"),
    509: ("NOUA", "IEik", "Automation flag ($[eT]: e ? 'IEik' : 'NOUA')"),
    520: (4023, 43885, "Site state ternary ($[mT]: e ? 43885 : 4023)"),
    527: (True, False, "window.chrome runtime integrity ($[527] = d(rf, e))"),
    543: ([], [], "Interaction events array ($[543] = f(qp, t))"),
    545: (False, True, "WebKit / ApplePaySession check ($[rE] = f(Jp, e))"),
    559: (56067, 27404, "Behavior probe ternary ($[Hv]: e ? 27404 : 56067)"),
    563: ("m", "K", "Pointer state flag ($[qy]: e ? 'K' : 'm')"),
    572: (52692, 16377, "Pointer/Touch ternary ($[Vy]: e ? 16377 : 52692)"),
    587: ("I", "Sb", "Opera window.opr check ($[PS]: e ? 'Sb' : 'I')"),
    617: ([], [], "Session telemetry array ($[ML] = u(Lf, MK()))"),
}


def _deterministic_u32(seed_str: str, idx: int) -> int:
    """Sinh giá trị hash 32-bit tất định (deterministic) cho các trường fingerprint."""
    h = 0x811C9DC5 ^ (idx & 0xFFFFFFFF)
    for ch in f"{seed_str}:{idx}":
        h = _imul(h ^ ord(ch), 0x01000193)
    return h & 0xFFFFFFFF


def _deterministic_pair(seed_str: str, idx: int) -> List[int]:
    """Sinh cặp [uint32, uint32] tất định cho các trường hash pair."""
    return [
        _deterministic_u32(seed_str + ":hi", idx),
        _deterministic_u32(seed_str + ":lo", idx),
    ]


# ===========================================================================
# 5. BỘ SINH CÁC FIELD CHƯA MÃ HOÁ (UNENCRYPTED FIELD GENERATOR)
# ===========================================================================

class CastleFieldGenerator:
    """
    Bộ sinh toàn bộ các field chưa mã hoá (human-readable / plaintext)
    cho Castle V1 (749 metrics), V2 (768 metrics), và V3 (772 metrics).
    """

    def __init__(self, workspace_dir: Optional[str] = None):
        self.workspace_dir = workspace_dir or os.path.dirname(os.path.abspath(__file__))
        self._v1_cipher_spec: Optional[Dict[int, Dict[str, Any]]] = None

    def get_v1_cipher_spec(self) -> Dict[int, Dict[str, Any]]:
        """
        Phân tích trực tiếp castle.umd-B6QTm2FJ.js và scope_extracted.json để lấy
        bản đồ mã hoá cấp trường cho toàn bộ 749 chỉ số (0..748) của V1.
        """
        if self._v1_cipher_spec is not None:
            return self._v1_cipher_spec

        spec: Dict[int, Dict[str, Any]] = {}
        se_path = os.path.join(self.workspace_dir, "scope_extracted.json")
        js_path = os.path.join(self.workspace_dir, "castle.umd-B6QTm2FJ.js")

        if not (os.path.exists(se_path) and os.path.exists(js_path)):
            self._v1_cipher_spec = spec
            return spec

        try:
            with open(se_path, "r", encoding="utf-8") as f:
                d = json.load(f)
            with open(js_path, "r", encoding="utf-8") as f:
                js = f.read()

            id_ops = {
                "u": {"Qd", "Lf", "Bf"},
                "d": {"rf", "cp", "Ff", "Ud"},
                "f": {"Bf", "Wf", "Cf", "zp", "Hp", "Up", "qp", "Mf", "Jp"},
                "p": {"Np", "yp"},
            }
            on_ops = {
                "u": {"6", "Ud", "Yd", "nf", "rf", "df", "ff", "pf", "mf", "gf", "_f", "vf", "xf", "Cf", "Ef", "Df", "Of", "Pf", "Rf", "1", "4", "Zd", "zf", "Gf", "qf", "np", "Jd", "ap", "sp", "cp", "pp", "vp", "2", "v", "xp", "Sp", "Dp", "Op", "Hf", "Ap", "Pp", "Fp", "_", "Rp", "qp", "Yp", "Xp"},
                "d": {"0", "2", "4", "6", "8", "tf", "bp", "Bd", "Vf", "Tp", "Wf", "cf", "Kf", "uf", "Ap", "Vd", "Mp", "tp", "xf", "Rp", "Cf", "zp", "Up", "fp", "mp", "9", "Hd", "Xd", "Bf", "Uf", "Op", "df", "Np", "np", "b", "wf", "y", "Wp", "Af", "Mf", "Xp", "If", "Rf", "Hp", "lp", "Of"},
                "f": {"0", "1", "2", "3", "5", "6", "9", "Wd", "Gd", "Qd", "Kd", "Yd", "Sp", "nf", "rf", "Bd", "Vf", "Tp", "Ep", "cf", "Dp", "Kf", "Jf", "pf", "Xf", "jp", "Qf", "Np", "gf", "Pp", "yf", "Lp", "bf", "rp", "xf", "Rp", "Sf", "y", "lp", "Of", "dp", "Gp", "fp", "pp", "Nf", "gp", "Xp", "Ff", "If", "vp", "Lf", "yp", "Rf"},
                "p": {"2", "5", "6", "ef", "v", "Zd", "xp", "Sp", "nf", "Bd", "Ep", "cf", "Dp", "Op", "df", "kp", "Yf", "jp", "Zf", "ep", "_f", "np", "Ip", "b", "bf", "rp", "_", "xf", "Rp", "Sf", "op", "wf", "Vp", "Ef", "Hp", "kf", "Af", "Mf", "Jp", "gp", "Ff", "vp", "Zp"},
            }
            mn_ops = {
                "u": {"cf", "Yf"},
                "d": {"ff", "S", "rp", "up", "Lf", "Zd", "af", "Ip", "Sf", "ip"},
                "f": {"Hd", "bp", "xp", "qd", "Yf", "Zf", "wf", "Af"},
                "p": {"9", "tf", "rf", "af", "Vf", "Uf", "qf", "Jf", "S", "gf", "Lp", "ip", "Cf", "Tf", "Up", "Of", "Wp", "jf", "Yp", "Xp", "If"},
            }
            pn_ops = {
                "u": {"Vd", "Sf", "Kf", "wp", "Vp", "Up", "Wp", "Gp"},
                "d": {"Qd", "zf", "qp", "5", "pf", "Bp", "Ef", "dp", "Pf"},
                "f": {"7", "Ud", "Xd", "Gf", "vf", "Ip", "kf", "jf", "Pf", "Yp", "$f"},
                "p": {"Ud", "Cp", "of", "pf", "Nf", "Qp"},
            }

            def _val(sym: str) -> int:
                return int(sym) if sym.isdigit() else int(d[sym])

            def _u32_syms(a: str, b: str, c: str, d_: str) -> int:
                return ((_val(a) << 24) | (_val(b) << 16) | (_val(c) << 8) | _val(d_)) & 0xFFFFFFFF

            # Hằng số của hàm Id(e)
            id_consts = (
                _u32_syms("bx", "ey", "_k", "T"),
                _u32_syms("JD", "Px", "I_", "Gx"),
                _u32_syms("E_", "Ty", "zb", "Ly"),
                _u32_syms("bx", "ey", "_k", "T"),
                _u32_syms("JD", "Px", "I_", "gS"),
            )

            for m in re.finditer(r"(?<![A-Za-z0-9_])\$(\[[^\]]+\])=", js):
                idx_s = m.group(1)[1:-1]
                idx_v = int(idx_s) if idx_s.isdigit() else d.get(idx_s)
                if not isinstance(idx_v, int) or idx_v in spec:
                    continue
                rhs = js[m.end() : m.end() + 1200]
                m_disp = re.match(r"^([udfp])\(([A-Za-z0-9_$]+),", rhs)
                if rhs.startswith("Fd("):
                    spec[idx_v] = {"cipher": "fd"}
                elif rhs.startswith("Pn("):
                    spec[idx_v] = {"cipher": "pn"}
                elif re.match(r"^\([a-z]=[^,]+,On\(", rhs):
                    spec[idx_v] = {"cipher": "on"}
                elif rhs.startswith("Id("):
                    spec[idx_v] = {"cipher": "pair_or_int", "consts": id_consts}
                elif rhs.startswith("function(e){var t=u(b"):
                    mp = re.search(
                        r"d\(gf,X,[a-zA-Z0-9_\[\]]+,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,T,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,T\).*?u\(x,[a-zA-Z0-9_\[\]]+,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T\)",
                        rhs,
                    )
                    if mp:
                        g = mp.groups()
                        spec[idx_v] = {
                            "cipher": "pair_or_int",
                            "consts": (
                                _u32_syms(g[0], g[1], g[2], g[3]),
                                _u32_syms(g[4], g[5], g[6], g[7]),
                                _u32_syms(g[8], g[9], g[10], g[11]),
                                _u32_syms(g[12], g[13], g[14], g[15]),
                                _u32_syms(g[16], g[17], g[18], g[19]),
                            ),
                        }
                elif rhs.startswith("function(e){var t=[]"):
                    m1 = re.search(r"p\(cp,[a-zA-Z0-9_\[\]]+,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,T\)", rhs)
                    m2 = re.search(r"p\(hf,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T\)", rhs)
                    m3 = re.search(r"p\(sf,[a-zA-Z0-9_\[\]]+,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,T\)", rhs)
                    m4 = re.search(r"u\(x,[a-zA-Z0-9_\[\]]+,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),q,([A-Za-z0-9_$]+),z,([A-Za-z0-9_$]+),T\)", rhs)
                    if m1 and m2 and m3 and m4:
                        spec[idx_v] = {
                            "cipher": "pair_or_int",
                            "consts": (
                                _u32_syms(*m1.groups()),
                                _u32_syms(*m2.groups()),
                                _u32_syms(*m3.groups()),
                                _u32_syms(*m4.groups()[:4]),
                                _u32_syms(*m4.groups()[4:]),
                            ),
                        }
                elif m_disp:
                    disp, op = m_disp.group(1), m_disp.group(2)
                    if op in id_ops[disp]:
                        spec[idx_v] = {"cipher": "unencrypted"}
                    elif op in on_ops[disp]:
                        spec[idx_v] = {"cipher": "on"}
                    elif op in mn_ops[disp]:
                        spec[idx_v] = {"cipher": "mn"}
                    elif op in pn_ops[disp]:
                        spec[idx_v] = {"cipher": "pn"}
                    else:
                        spec[idx_v] = {"cipher": "self_hash" if 658 <= idx_v <= 667 else "unencrypted"}
                else:
                    spec[idx_v] = {"cipher": "unencrypted"}
        except Exception:
            pass

        self._v1_cipher_spec = spec
        return spec

    def generate_unencrypted_v1(
        self,
        profile: Optional[ClientProfile] = None,
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        is_bot: bool = False,
    ) -> List[Any]:
        """
        Sinh toàn bộ 749 field chưa mã hoá (plaintext / human-readable) cho V1 (uq1seNrd).
        """
        p = profile or ClientProfile()
        metrics: List[Any] = [165] * 749

        # 1. Áp dụng các trường trực tiếp / chưa mã hoá (direct & ternary flags) từ castle.umd-B6QTm2FJ.js
        for idx, (clean_val, bot_val, _desc) in V1_DIRECT_UNENCRYPTED_DEFAULTS.items():
            metrics[idx] = bot_val if is_bot else clean_val

        # 2. Áp dụng các trường đã định danh trong METRIC_LABELS (ở dạng chưa mã hoá)
        metrics[0] = "l" if is_bot else "F"
        metrics[1] = p.screen_width
        metrics[2] = p.screen_height
        metrics[6] = int(p.canvas_hash, 16) if isinstance(p.canvas_hash, str) else p.canvas_hash
        metrics[8] = int(p.audio_hash, 16) if isinstance(p.audio_hash, str) else p.audio_hash
        metrics[9] = p.color_depth
        metrics[11] = "xLp" if is_bot else "t"
        metrics[16] = int(p.device_pixel_ratio)
        metrics[22] = True if is_bot else p.webdriver_active
        metrics[40] = p.locale
        metrics[44] = True if is_bot else p.automation_detected
        metrics[59] = f"{p.operating_system} (x86_64)" if p.operating_system == "Windows" else p.operating_system
        metrics[61] = 0
        metrics[86] = int(p.webgl_fp, 16) if isinstance(p.webgl_fp, str) else p.webgl_fp
        metrics[143] = True if is_bot else p.headless_detected
        metrics[151] = True if is_bot else p.devtools_open
        metrics[163] = p.device_guid
        metrics[383] = True if is_bot else p.cdp_active
        metrics[406] = p.ip_address
        metrics[551] = f"{p.browser_name} {p.browser_version}".strip()

        # 3. Sinh thời gian thực thi probe (chưa mã hoá, đơn vị ms float) cho các chỉ số 668..748
        rng = random.Random(42)
        for i in range(668, 749):
            metrics[i] = round(rng.uniform(0.1, 4.5), 2)

        # 4. Áp dụng overrides theo slug hoặc index
        if overrides:
            slug_to_idx = {slug: idx for idx, (slug, _title) in METRIC_LABELS.items()}
            for k, v in overrides.items():
                if isinstance(k, int) and 0 <= k < 749:
                    metrics[k] = v
                elif isinstance(k, str):
                    if k.isdigit() and 0 <= int(k) < 749:
                        metrics[int(k)] = v
                    elif k in slug_to_idx:
                        metrics[slug_to_idx[k]] = v

        return metrics

    def generate_unencrypted_v2(
        self,
        profile: Optional[ClientProfile] = None,
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        is_bot: bool = False,
    ) -> List[Any]:
        """
        Sinh toàn bộ 768 field chưa mã hoá (plaintext / human-readable) cho V2 (cNz8rPYH).
        """
        p = profile or ClientProfile()
        metrics: List[Any] = [165] * 768
        seed = f"{p.user_agent}|{p.gpu_renderer}|{p.device_guid}"

        # Các trường mặc định hệ thống, trình duyệt, mạng, màn hình, phiên (chưa mã hoá)
        v2_defaults: Dict[int, Any] = {
            0: 1,
            1: "cNz8rPYH",
            2: 2,
            4: _deterministic_u32(seed, 4),
            5: 1,
            6: p.canvas_hash,
            7: _deterministic_u32(seed, 7),
            8: p.operating_system,
            9: _deterministic_u32(p.operating_system, 9),
            10: _deterministic_u32(p.engine_version, 10),
            11: p.arch_bits,
            12: _deterministic_u32(seed, 12),
            13: _deterministic_u32(p.architecture, 13),
            14: _deterministic_u32(str(p.device_memory), 14),
            15: _deterministic_u32(str(p.color_depth), 15),
            16: _deterministic_pair(f"{p.screen_width}x{p.screen_height}", 16),
            17: _deterministic_u32(str(p.device_pixel_ratio), 17),
            18: _deterministic_u32(p.timezone, 18),
            19: p.tz_offset_raw,
            20: f"{p.screen_width}x{p.screen_height}",
            22: True if is_bot else p.webdriver_active,
            23: _deterministic_u32(p.gpu_renderer, 23),
            24: "probably",
            25: p.castle_pubkey,
            26: p.render_engine,
            27: _deterministic_u32(p.render_engine, 27),
            28: p.engine_version,
            36: False,
            41: False,
            43: 12,
            44: True if is_bot else p.automation_detected,
            52: "normal",
            53: p.screen_width,
            60: p.gpu_renderer,
            61: 100,
            63: p.user_agent,
            67: p.locale,
            68: p.cookie_flag,
            72: _deterministic_pair(seed, 72),
            75: p.hw_concurrency,
            79: False,
            80: p.request_id,
            83: p.audio_sample_rate,
            88: "en-US",
            96: 0,
            97: 0,
            98: 0,
            101: p.browser_name,
            103: p.browser_vendor,
            106: False,
            107: p.visibility,
            109: p.shader_hash_str,
            111: _deterministic_u32(seed, 111),
            116: p.css_selector_fp,
            117: p.error_probe_type,
            118: 161,
            127: 1,
            135: p.canvas_hash,
            137: "probably",
            139: p.webgl_fp,
            140: 0,
            143: True if is_bot else p.headless_detected,
            145: 0,
            148: p.locale,
            149: _deterministic_u32(p.locale, 149),
            151: True if is_bot else p.devtools_open,
            152: p.locale,
            154: p.timezone,
            159: p.tz_offset_raw,
            161: p.language,
            165: 1,
            166: p.date_probe,
            178: "1",
            180: _deterministic_pair(seed, 180),
            182: 0,
            189: 1,
            192: 0,
            194: _deterministic_pair(seed, 194),
            196: False,
            203: 1,
            205: 1,
            207: False,
            214: 1,
            215: p.ua_brands,
            217: "131",
            221: 1,
            224: p.timezone,
            226: p.tz_offset_raw,
            230: "N",
            233: 1,
            235: p.gpu_renderer,
            239: f"{_deterministic_u32(seed, 239):08x}",
            240: False,
            242: p.browser_ver_detail,
            244: p.error_probe_prop,
            247: p.display_type,
            248: p.browser_version,
            252: p.screen_height,
            253: False,
            260: p.origin_url,
            269: 15,
            272: 200,
            280: True,
            284: p.engine_version,
            293: p.accept_langs,
            303: "activated",
            308: p.page_title,
            311: 1,
            316: False,
            324: p.os_arch,
            325: 10,
            327: 5,
            332: p.gpu_vendor,
            334: p.color_depth,
            341: p.last_event,
            342: 1,
            343: 42,
            352: p.screen_orient,
            353: 0,
            359: p.protocol,
            363: 1,
            365: "N",
            366: p.platform,
            367: p.platform_sub,
            368: p.architecture,
            373: _deterministic_u32(seed, 373),
            374: False,
            380: p.device_memory,
            383: True if is_bot else p.cdp_active,
            391: "N",
            395: "N",
            396: 0,
            397: False,
            398: _deterministic_pair(f"{p.screen_width}x{p.screen_height}", 398),
            402: "N",
            403: 12,
            404: p.history_length,
            406: _deterministic_u32(p.ip_address, 406),
            416: p.build_id,
            418: 1,
            419: p.error_probe_inv,
            427: False,
            432: 0,
            437: f"{_deterministic_u32(seed, 437):08x}",
            438: p.feature_flags_bin,
            444: 0,
            445: p.audio_max_channels,
            448: "1",
            458: "probably",
            460: p.pdf_viewer_enabled,
            463: p.screen_width,
            466: False,
            469: f"{_deterministic_u32(seed, 469):08x}",
            471: 1,
            473: p.ip_address,
            476: p.webrtc_cand_type,
            482: f"{_deterministic_u32(seed, 482):08x}",
            483: 1,
            485: 0,
            490: p.locale,
            492: f"{_deterministic_u32(seed, 492):08x}",
            496: False,
            502: False,
            517: 1,
            520: p.site_domain,
            523: 1,
            529: p.shader_source,
            530: 1,
            533: 1,
            541: 0,
            542: p.url_path,
            543: False,
            550: "1",
            561: 1,
            567: 0,
            568: 0,
            577: False,
            579: p.proto_probe,
            581: False,
            588: 2,
            589: 5,
            590: False,
            599: f"{_deterministic_u32(seed, 599):08x}",
            609: p.secondary_ts,
            617: "1",
            619: p.stack_probe,
            622: p.session_id,
            629: 1,
            631: p.session_id,
            632: False,
            638: p.user_agent,
            643: p.nav_type,
            645: p.ua_brands_short,
            647: f"{_deterministic_u32(seed, 647):08x}",
            655: 15,
            658: p.screen_width,
            659: p.webrtc_proto,
            661: 1,
            665: p.zero_flags,
            668: p.device_guid,
            670: f"{_deterministic_u32(seed, 670):04x}",
            671: 18,
            673: "1",
            674: 0,
            677: 22,
            679: f"{_deterministic_u32(seed, 679):04x}",
        }

        for idx, val in v2_defaults.items():
            metrics[idx] = val

        # Sinh thời gian thực thi probe (chưa mã hoá, float ms) cho các chỉ số 683..767
        rng = random.Random(102)
        sync_total = 0.0
        for i in range(683, 747):
            dur = round(rng.uniform(0.05, 1.8), 2)
            metrics[i] = dur
            sync_total += dur
        metrics[747] = round(sync_total, 2)
        async_total = 0.0
        for i in range(750, 768):
            dur = round(rng.uniform(0.2, 6.5), 2)
            metrics[i] = dur
            async_total += dur
        metrics[749] = round(async_total, 2)
        metrics[748] = round(sync_total + async_total + rng.uniform(1.0, 3.5), 2)

        # Áp dụng overrides theo slug hoặc index
        if overrides:
            slug_to_idx = {slug: idx for idx, (slug, _title, _cat) in METRIC_INFO_V2.items()}
            for k, v in overrides.items():
                if isinstance(k, int) and 0 <= k < 768:
                    metrics[k] = v
                elif isinstance(k, str):
                    if k.isdigit() and 0 <= int(k) < 768:
                        metrics[int(k)] = v
                    elif k in slug_to_idx:
                        metrics[slug_to_idx[k]] = v

        return metrics

    def generate_unencrypted_v3(
        self,
        profile: Optional[ClientProfile] = None,
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        is_bot: bool = False,
    ) -> List[Any]:
        """
        Sinh toàn bộ 772 field chưa mã hoá (plaintext / human-readable) cho V3 (WcmFKZlD)
        dựa trên template đầy đủ 772 phần tử của mẫu V3 thực tế (không còn phần tử 165 rỗng).
        """
        p = profile or ClientProfile()
        metrics: List[Any] = list(V3_REAL_BASELINE_RAW)

        # 1. Giải mã toàn bộ các trường chuỗi Gn() (37 trường) và Kn() (32 trường) trong baseline sang plaintext
        for idx in V3_GN_STR_INDICES:
            dec = decode_gn(metrics[idx])
            if dec is not None:
                metrics[idx] = dec
        for idx in V3_KN_STR_INDICES:
            dec = decode_kn(metrics[idx])
            if dec is not None:
                metrics[idx] = dec

        # 2. Giải mã các trường số nguyên Group A và Group B thuộc profile sang plaintext
        for idx in V3_INT_A_PROFILE_INDICES:
            dec_i = decode_v3_int_a(metrics[idx])
            if dec_i is not None:
                metrics[idx] = dec_i
        for idx in V3_INT_B_PROFILE_INDICES:
            dec_b = decode_v3_int_b(metrics[idx])
            if dec_b is not None:
                metrics[idx] = dec_b

        # 3. Giải mã 85 trường thời gian thực thi probe (687..771) giữ nguyên float32 chính xác của trình duyệt
        for idx in range(687, 772):
            fval = decode_qd_float32_exact(metrics[idx])
            if fval is not None:
                metrics[idx] = fval

        # 4. Áp dụng các trường động từ ClientProfile
        canvas_hex = f"{p.canvas_hash:08x}" if isinstance(p.canvas_hash, int) else str(p.canvas_hash)
        audio_hex = f"{p.audio_hash:08x}" if isinstance(p.audio_hash, int) else str(p.audio_hash)
        webgl_hex = f"{p.webgl_fp:08x}" if isinstance(p.webgl_fp, int) else str(p.webgl_fp)
        sec_ts_str = str(p.secondary_ts)

        v3_defaults: Dict[int, Any] = {
            10: canvas_hex,
            21: p.architecture,
            22: p.inner_width,
            29: p.browser_ver_detail,
            43: True if is_bot else p.webdriver_active,
            53: encode_v3_os_field(p.operating_system, p.architecture),
            57: p.engine_version,
            60: p.tz_offset_raw,
            64: p.locale,
            68: True if is_bot else p.automation_detected,
            77: p.error_probe_type,
            78: encode_v3_shader_field(p.shader_hash_str),
            84: p.session_id,
            85: p.hw_concurrency,
            87: p.operating_system,
            89: p.timezone,
            92: True if is_bot else False,
            96: p.user_agent,
            98: p.error_probe_inv,
            100: p.feature_flags_bin,
            108: p.engine_version,
            121: p.display_type,
            122: p.accept_langs,
            125: p.platform,
            135: p.language,
            157: p.origin_url,
            160: p.device_guid,
            163: p.screen_width,
            168: p.css_selector_fp,
            169: p.castle_pubkey,
            174: sec_ts_str,
            176: True if is_bot else False,
            179: audio_hex,
            183: p.date_probe,
            209: p.local_ip_fallback,
            212: p.ip_address,
            218: True if is_bot else p.chrome_runtime_flag,
            223: p.color_depth,
            228: True if is_bot else False,
            232: p.session_id,
            237: p.gpu_renderer,
            244: True if is_bot else False,
            258: p.inner_height,
            265: webgl_hex,
            296: p.gpu_renderer,
            306: p.shader_source,
            311: p.gpu_arch,
            355: True if is_bot else p.headless_detected,
            373: p.zero_flags,
            375: p.window_prop_check,
            396: p.hw_concurrency,
            398: p.browser_vendor,
            402: p.arch_bits,
            412: p.page_title,
            414: p.screen_orient,
            416: True if is_bot else False,
            431: p.error_probe_prop,
            433: p.webrtc_proto,
            445: "rFzj" if (is_bot or p.cdp_active) else p.cdp_code,
            477: p.chrome_obj_present,
            483: p.screen_height,
            492: p.render_engine,
            504: p.build_id,
            506: True if is_bot else p.selenium_cdc_flag,
            510: p.perf_memory_present,
            512: p.visibility,
            517: p.chrome_csi_present,
            522: p.user_agent,
            523: p.ua_brands,
            527: True if is_bot else False,
            533: p.protocol,
            535: True if is_bot else False,
            538: p.nav_type,
            555: p.last_event,
            558: p.proto_probe,
            573: p.gpu_vendor,
            578: -int(p.screen_width),
            592: p.browser_name,
            597: p.stack_probe,
            598: p.site_domain,
            632: p.ua_brands_short,
            636: p.url_path,
            647: p.screen_width,
            655: p.feature_support_flag,
            668: p.device_memory,
            670: p.browser_version,
            678: p.tz_offset_hex,
            684: str(p.history_length),
        }

        for idx, val in v3_defaults.items():
            metrics[idx] = val

        # 5. Áp dụng overrides theo slug hoặc index
        if overrides:
            slug_to_idx = {slug: idx for idx, (slug, _title, _cat) in METRIC_INFO_V3.items()}
            for k, v in overrides.items():
                if isinstance(k, int) and 0 <= k < 772:
                    metrics[k] = v
                elif isinstance(k, str):
                    if k.isdigit() and 0 <= int(k) < 772:
                        metrics[int(k)] = v
                    elif k in slug_to_idx:
                        metrics[slug_to_idx[k]] = v

        return metrics

    def generate_unencrypted_v4(
        self,
        profile: Optional[ClientProfile] = None,
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        is_bot: bool = False,
    ) -> List[Any]:
        p = profile or ClientProfile()
        metrics: List[Any] = list(V4_REAL_BASELINE_RAW)

        canvas_hex = f"{p.canvas_hash:08x}" if isinstance(p.canvas_hash, int) else str(p.canvas_hash)
        audio_hex = f"{p.audio_hash:08x}" if isinstance(p.audio_hash, int) else str(p.audio_hash)
        webgl_hex = f"{p.webgl_fp:08x}" if isinstance(p.webgl_fp, int) else str(p.webgl_fp)
        sec_ts_str = str(p.secondary_ts)

        v4_defaults: Dict[int, Any] = {
            1: p.page_title if p.page_title else metrics[1],
            71: p.architecture,
            111: p.gpu_renderer,
            133: "639206892",
            154: str(p.device_guid),
            159: canvas_hex,
            173: p.browser_version,
            186: p.castle_pubkey,
            190: p.webrtc_proto,
            192: p.locale,
            257: p.browser_version,
            263: p.gpu_vendor,
            269: "10.0.0" if "Windows" in p.operating_system else "1.0.0",
            278: p.gpu_arch,
            310: p.operating_system,
            311: p.browser_name,
            314: p.platform,
            350: p.screen_orient,
            428: p.gpu_renderer,
            429: p.ip_address,
            436: p.session_id,
            458: p.ua_brands_short,
            463: p.accept_langs,
            483: p.user_agent,
            505: p.protocol,
            544: p.user_agent,
            548: p.timezone,
            554: p.url_path,
            604: p.browser_vendor,
            606: p.ua_brands,
            618: p.origin_url,
            620: p.site_domain,
            646: "udg" if is_bot else "kpgg",
        }

        for idx, val in v4_defaults.items():
            if val is not None and 0 <= idx < len(metrics):
                metrics[idx] = val

        if overrides:
            slug_to_idx = {slug: idx for idx, (slug, _title, _cat) in METRIC_INFO_V4.items()}
            for k, v in overrides.items():
                if isinstance(k, int) and 0 <= k < len(metrics):
                    metrics[k] = v
                elif isinstance(k, str):
                    if k.isdigit() and 0 <= int(k) < len(metrics):
                        metrics[int(k)] = v
                    elif k in slug_to_idx:
                        metrics[slug_to_idx[k]] = v

        return metrics

    def generate_unencrypted_metrics(
        self,
        version: Union[int, str] = 3,
        profile: Optional[ClientProfile] = None,
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        is_bot: bool = False,
    ) -> List[Any]:
        """Hàm tổng hợp sinh mảng metrics chưa mã hoá cho phiên bản V1, V2, V3 hoặc V4."""
        ver = self._normalize_version(version)
        if ver == 1:
            return self.generate_unencrypted_v1(profile=profile, overrides=overrides, is_bot=is_bot)
        if ver == 2:
            return self.generate_unencrypted_v2(profile=profile, overrides=overrides, is_bot=is_bot)
        if ver == 4:
            return self.generate_unencrypted_v4(profile=profile, overrides=overrides, is_bot=is_bot)
        return self.generate_unencrypted_v3(profile=profile, overrides=overrides, is_bot=is_bot)

    @staticmethod
    def _normalize_version(version: Union[int, str]) -> int:
        if isinstance(version, int):
            return version if version in (1, 2, 3, 4) else 4
        v = str(version).strip().lower()
        if v in ("1", "v1", "uq1senrd"):
            return 1
        if v in ("2", "v2", "cnz8rpyh"):
            return 2
        if v in ("3", "v3", "wcmfkzld"):
            return 3
        if v in ("4", "v4", "ezk-f_qb", "ezkf_qb"):
            return 4
        return 4


# ===========================================================================
# 5B. BẢN ĐỒ MÃ HOÁ CẤP TRƯỜNG V3 (Gn / Kn / Raw / Int_A / Int_B) & BASELINE 772 METRICS
# ===========================================================================

# 37 chỉ số chuỗi mã hoá bằng Gn() trong V3 (WcmFKZlD)
V3_GN_STR_INDICES = frozenset({
    0, 10, 21, 64, 77, 84, 87, 105, 121, 125, 135, 160, 180, 183, 232,
    296, 311, 393, 398, 412, 414, 430, 431, 433, 497, 504, 520, 522, 533,
    555, 573, 597, 598, 632, 636, 650, 670,
})

# 32 chỉ số chuỗi mã hoá bằng Kn() trong V3 (WcmFKZlD)
V3_KN_STR_INDICES = frozenset({
    34, 57, 89, 96, 98, 100, 108, 122, 157, 168, 169, 174, 179, 209, 221,
    237, 255, 265, 306, 373, 402, 444, 463, 492, 512, 523, 538, 558, 592,
    678, 682, 684,
})

# 34 chỉ số chuỗi giữ nguyên (Raw String / Binary Packed String, KHÔNG mã hoá Gn/Kn) trong V3
V3_RAW_STR_INDICES = frozenset({
    15, 24, 28, 29, 30, 47, 49, 53, 78, 80, 124, 126, 133, 146, 167,
    189, 204, 212, 333, 356, 357, 421, 445, 459, 470, 471, 532, 571,
    574, 585, 587, 588, 596, 630,
})

# Các chỉ số số nguyên thuộc Profile mã hoá theo Group A Integer Cipher và Group B Integer Cipher
V3_INT_A_PROFILE_INDICES = frozenset({22, 60, 163, 223, 258, 483, 578, 647, 668})
V3_INT_B_PROFILE_INDICES = frozenset({85, 396})

V4_REAL_BASELINE_RAW = (4293368605, 'O0TLRntGw0MbRUJG80R7RhNFu0SDRBtFQkbzRHtGu0SDRPtE+0SjRMtEw0TLRJNEe0bTRntGO0Q=', 1530643103, 1418710237, 3349463409, 1135299, -293, 2613693720, 61580, 1761607689, 2321553135, 1377183021, 1761607689, 1761607689, 3493902965, 1445512083, 1182513581, 1135299, [436278284, 443524134], 1644167177, 2444128801, -293, 3724782185, 'vj', 9573, 1902900322, 2212345888, 4055344289, 1130364, -293, 770801451, 12776, 1761607689, 3469519621, 4294207555, 2054386675, 1627961437, -302, 1135299, 973078547, 'RMd', 144000868, 3060509206, 1465198815, 1135299, 2713194743, 1850243469, -293, 1761607689, 2855012788, 1761607689, 1135299, 303497227, 1166209779, 53116945, 1950771306, 2653004122, 1557856327, 881162077, 2844862591, 3260200407, 2694714767, 1761607689, -293, 4286319451, 2535491913, 2826565610, 381913226, 2436763826, 290140543, 'e4ab5ce0[]w3c[]hlsl', 'x86', 3808743980, 1644167177, 4716, 23372, 6015, 3340712080, 1135299, 1778384905, -475, 1761607689, 2196354021, 1135299, [345710901, 1437511161], 1854829594, 1135299, -293, '', 1761607689, -293, 'AnTz', 1133325, -294, 'navigate', -293, 1761607689, 3949897306, 1761607689, [3975829323, 3512442141], 150994959, 1761607689, -466, 963903814, 'L00000d158703800187001587c6000787c6041a15d3c60405001ac3c604021a1587c6041a8000i5duj5745', 4076051766, 1761607689, 4294207555, 3364471154, 2378164210, 3412133113, 'ANGLE (NVIDIA, NVIDIA GeForce GT 710 (0x0000128B) Direct3D11 vs_5_0 ps_5_0, D3D11)', 1135299, 2942839449, 'Yy', -293, 2277781591, 'probably', False, [703470760, 2225322817], 2794157962, 190898111, 797058397, -293, 1134312, 1135299, -922746867, 3677799066, 4145198989, [4110297431, 3617358604], 1778384905, -905969596, 'bS', '639206892', 62538, 2997784226, -293, 3903604929, 1452252823, -293, [3317361105, 345366548], 2081330930, 'Kb', '', 2131114725, [344787406, 1604285773], 4044116372, 1499632705, 4075736443, 787140309, 1135299, -293, 1524324783, 1244792680, '584705a1-112a-459c-9f93-b3225090eba5', 1134312, [4110382577, 3518935845], 1474879617, 1980579556, 'cc25e208', -2144503161, 62023, 4294703029, 3086012653, 1206968001, -294, 238443480, 1028832223, 4011895718, 1378965917, -293, -293, 1135299, '158.0.8127.37', 1983212697, 1051404, 759461242, 255733578, 563821696, -294, 2366183558, 1985346339, 3705330914, 1761607689, 2589888437, 543721488, 'pk_AvRa79bHyJSYSQHnRpcVtzyxetSvFerx', 2145856089, 887674082, -468, 'dtls-sctp+udp', 1135299, 'en-US', -293, -293, 'fa84436d', 60266, 1553564158, 2577744171, 3352610670, 29902, 1134312, 1644167177, 1737480431, 23519, 1158463578, 265682082, -293, 1135299, 1254306718, 'RangeError', 'Rh', -294, 4181050635, 2051121710, 26787, 2223396495, -385875957, 'ca945b0e', 1801619380, 264484006, 1134312, 975558958, 743397671, 1761607689, 427747625, 3361046745, -294, 2311133167, 1309111237, 1761607689, 1336308293, 2658085643, 1644167177, 1130364, 894471, 2182113222, 3156068104, 1049381116, 228246, 1644167177, 4058571677, 'db77b610', 'HHm', 2162445569, 4156789597, 'e11d254', -293, 2657069652, 417709412, 1761607689, 3682280691, 3573382261, '1111111111111111111111111111111111111000000000', 1326421317, 2189789705, -294, '158.0.8127.37', -479, 3177367381, 434410762, 1099971038, 53199, 'nvidia', 919775098, 1160236478, -293, 438857600, 3977953486, '10.0.0', 2891216860, 1147101710, 48612, '', 1170245320, 3255164384, 244490896, 1761607689, 'kepler', 2846591049, 2540728748, 1134312, 1644167177, 1673752103, 4287408112, 3063507328, 1853281202, 'RAEAfwO1eVcFAAP5Y9mWAAMXVKEWAAMGBTpyb290LwMILnItbWZoZzBhAjFbZGF0YS1zb25uZXItdG9hc3Rlcl1bZGlyPSJsdHIiXSwgaHRtbFtkaXI9Imx0ciJd6QJhEy5qZXRmdWVsLXN0eWxlLXJvb3SKBuIEHi5qZXRmdWVsLXN0eWxlLXJvb3QgLmotYnJsYzNkMDefAQYucUpUSE3jAVGAAwrUA6tBAk4yTexkBnRJYgAGdEliAAZ0SWIABnRJYgAGdEliAAZ0SWIALA4rjQAGdEliADx0YqABAAD8EK4OAQAA/BCuDqAJkLXm/PHsDnW6zgEtNzsOAaf4MDIBLTc7DiMiAAMDb8mW/sjW2pB5x/gE', 3134025794, 1134312, 53445749, 1046610442, -293, 3732019114, 1676885617, 3580221023, 1761607689, -293, 962303198, 3378567259, 1761607689, 'mousewheel', 67072437, 1127403, 1135299, 50540, 3036136217, 3028006545, 2901043255, '0000000000000000000000000000000000000000000', 'Windows', 'Google Chrome', 1135299, 'bd4be70d', 'Win32', [3418704335, 1553202146], 1134312, 694429999, 3880786239, 2047610112, 3124257722, False, 842705137, 1134312, [3569118758, 4183515958], 876152567, -301, False, 1644167177, 3484340511, 1422647569, 3161910737, 1761607689, 2047842790, 1761607689, 3769148619, '3/1/1970, 7:00:00 AM', -476, [2343394990, 2181949088], [1947496558, 3854425540], 2457716958, 'string', 2653525164, 2245455670, 1761607689, 1761607689, 4015790056, -294, -294, 1134312, 'landscape-primary', -293, -293, 2492147335, 1135299, -294, 2438843180, 1776780505, 2328472797, 768777394, 1455765497, 3235569594, False, 1543270845, 2614488241, 3626723661, 1135299, 281251324, False, 1134312, 'gM', '// INITIAL HLSL BEGIN#pragma warning( disable: 3081 3556 3557 3571 )#ifdef ANGLE_ENABLE_LOOP_FLATTEN#define LOOP [lo', 946475045, 900164379, 1208725341, 2905226987, 3856899895, 4257142306, 'visible', 1392575354, 3938452425, 980504865, 1135299, 3365530613, 2681921478, 1135299, '', 1135299, '1795749303558', 95075554, 1761607689, 2759816829, 1006929934, 1684793702, [3692375207, 3963465088], '0.0.0.0', 702383182, 1321748180, 1135299, 1750631691, '', 1135299, 827790482, 4076530660, 4028824125, -671088610, 56716, [2840764817, 3837321102], 3487029837, 3381687935, 4216646628, '34b454a7', 3287161176, 3194886395, 3448829438, 'I', 3629447896, 2917755328, 2092266599, 1134312, 1761607689, 'Windows', '', 1134312, 3484310551, 1747439329, 893786232, 3176520277, 'ANGLE (NVIDIA, NVIDIA GeForce GT 710 (0x0000128B) Direct3D11 vs_5_0 ps_5_0, D3D11)', '42.117.25.219', 'S', 2881270230, 1134312, 'webkit', '64', 1660773447, '9tykz5c3p', 827790482, 902291075, 'probably', 3057468746, 1644167177, 584860969, 2773163330, 2584284970, -293, -293, 1817112487, 452984844, 2128898487, -473, -293, 3721112844, 45967, 956301321, 656098717, -471, 1610612834, '[{"brand":"Chromium","version":"158"},{"brand":"Not.A/Brand","version":"24"},{"brand":"Google Chrome","version":"158"}]', 1536338982, 'l', 1134312, '8fc90f7d', 'en-US,en', 153965301, 570425357, -293, 1427992364, '9tykz5c3p', 593359077, 1392575354, 1130346098, 3613841626, [1047273484, 1769658542], False, 1671345699, 4153567024, 3737274201, 1135299, 3338634325, 1135299, 'ugUf', 1761607689, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36', 2585984493, 4152215439, "Cannot read properties of undefined (reading 'b')", 719070558, 440879987, 1644167177, -293, 1761607689, 1027495959, [2432198051, 2051746519], 1644167177, 1135299, 3084569752, 'Maximum call stack size exceeded', 2702032269, 769628479, -1996488702, 1132338, 1761607689, 2001644120, 3868898285, 'https:', 2014891189, 3508129121, 3359602349, 2959866917, 1118520, 33380, 1171524810, 'UAnu', 3759716716, 1134312, 1135299, 1644167177, 2852322013, 4282851542, 3291818232, 2996261038, 1135299, 1761607689, 2223141609, 3874183367, 3481165730, 1206447814, 2184296070, 'en-US', 1761607689, 2344801326, 1273138657, 'TypeError: Cyclic __proto__ value', 2528633899, 1134312, 1926139656, 3202146180, 1333052322, 3389762697, -1476394999, 1761607689, 1135299, 1761607689, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36', 'screen', 1135299, 4269636695, 'Etc/GMT-7', 958539996, '', [3158485428, 3841139926], 1644167177, 3371012358, '/i/jf/onboarding/web', 1133325, 'v', 154497471, False, 'vsaH', '1000', -218103805, True, -293, 1644167177, -293, 719666294, 3062923054, 108819, 3115927515, 'maybe', 226420589, 1115, 2465403218, 1644167177, 2987230625, 8706, 50949, 2689108000, 3279449934, False, 1616315364, 3209535535, 1790236937, 'M', 'tYA', 482780203, 1251212231, False, 1761607689, 1761607689, 1761607689, 44483, 'fb0a4aff', 3256600054, 4261525362, -294, 3066135454, 914597904, '10.0.0', -293, 1818538655, 3025743911, 231920158, 'Google Inc.', 2030043276, '[{"brand":"Chromium","version":"158.0.8127.37"},{"brand":"Not.A/Brand","version":"24.0.0.0"},{"brand":"Google Chrome","version":"158.0.8127.37"}]', 1102728, 'xU', 'cjP', [399166584, 3899839149], 716111564, -293, 1986836962, 1427939444, 2232079493, 23462, 1041224577, 'https://x.com', '', 'x.com', 'cba5f63a', 'Fvr', 477732489, 1135299, 860913, 1761607689, 1091097136, False, 1644167177, -293, 3028984159, 4085530361, -293, 477356403, '20030107', 4216978633, 'Illegal invocation', 52384, 4107465881, 705936703, -294, 622121676, 3246044039, 'NA', 1618887667, 'kpgg', 887121918, 3134491410, 1761607689, 2648407784, 1135299, '', 1889736806, 2901272238, 3291944030, 722098866, 2184393562, True, 676792557, 1114443584, 3428929872, 'a6563aaf', 4248617800, 3464153525, 1660944393, 3414720394, 2234214945, 570697895, -467, 756219386, 1644167177, 997608760, 1761607689, 4131736953, 1736205770, 173872954, '6f013', 46915, 1306166655, 'a9', 'f', '557', 'dd22bfaf', 46, 2132381, 36064, 60994, 11172, 3349559420, 1076358260, 0.0, 0.3, 0.1, 0.0, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.4, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2, 1.4, 0.1, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.9, 0.0, 0.0, 0.1, 0.0, 0.0, 0.1, 0.1, 0.0, 0.1, 0.0, 0.1, 0.0, 0.1, 0.1, 0.3, 0.0, 0.1, 0.0, 0.0, 2.8, 0.0, 18.7, 0.0, 0.1, 0.1, 0.0, 0.2, 0.2, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 288.9, 0.3, 53.2, 0.0, 248.1, 312.3, 228.1, 227.2, 127.8, 279.3, 305.0, 21.9, 49.4, 228.5, 423.6, 229.7, 231.2, 277.9, 291.0, 264.9, 293.6)

# Template đầy đủ 772 phần tử trích xuất từ mẫu token V3 thực tế (Chrome 156 / Windows 10 / x.com)
V3_REAL_BASELINE_RAW: Tuple[Any, ...] = (
    'yOPFw8oTyPPJY8XDyNPKIw==', 2574259179, 3182360447, 500158818, 1882377213, 506839937, 1848472597,
    478400425, 478629162, 19707, 'ygPKI8kjygPKM8jTyWPKIw==', 3485301485, 8432, 1719301146, 49327,
    '\x03\u018c\t\x000000531587c6000780c6000715800056011b1587c6041a15d3c60404001a5603158000155601874600569d151b56ff1556061856831587460087c600071580c600071587c6041a15d3c60405001ac3c604021a15874513874600800115d346000000804600d3460000001587c513c687c6041a8001158000158780c7560815560118560c185602185647158780c7800015803f87c6041a1580008745131587451387c60007800115800087c6000780c60007d3c60004000756061580c60007d3c600040007158mshad8i0',
    1814792858, 49367, 1249128, 935321570, 2812212036, 'xOPI48jD', -1285281, 1296430285,
    '', 318200812, 900633911, 546037185, '', '156.0.8078.81', 's', 1247604,
    3166039022, 1613482402, 'f5l/pH+lf6R/p3+Zf5l/lA==', 418118440, 8397, 1221696, 921904221, 53462,
    446155127, 49367, 589297899, False, 2361641919, 49367, 834223032, 'Sl',
    1352742922, 'yY', 2572843751, 2028307929, 2760640521, '\x03\x07\x00\x03Windowsx86', 2418785436, 45841,
    [201684976, 2888005529], 'f6l/qn+sf6p/rH+q', 1678438557, 3089756474, 1064724, 896130889, 445386277,
    2955460645, 'yjPFQ8mzyzPLEw==', 3049810196, 2044566047, 1462652609, False, 49207, -2071023585,
    2675510750, 3233280627, 346768849, 49367, 49367, 3636798820, 'ywPKc8VDxdPKM8gzxQPFA8VTxQM=', '\x06\x03\x02\x02\x00\x08\x04w3c[][]e5f1648chlsl',
    1195788, 'poq', 1247604, 1431576935, 1555249599, 'yRPJM8kDyMPJM8UDxNPI08WDyhM=', 49271, 2800058695,
    'ytPF88VDyiPFU8TTxRM=', 46453, 'f7UAZn+Xf6t/s3+Nf4Z/rX+j', 49199, 1827525460, False, 2968395663, 49367,
    1249128, 'f40AawBgf5EAbgBuf5l/q3+lf6x/qn/af9J/g3+RAGx/lgBrAGMAZ3/af4x/hn/af6l/qn+sf6p/v3/af4N/kQBsf6R/pn+/f9oAYn+kf6Z/0X/af7kAagBqAG5/lX+Df5V/mH+Pf5EAZn+rf6V/p3+jf6x/p3+kf9p/0n+Pf7J/hn+Nf45/rn/aAG5/kQBvf5V/2n+zf5V/lwBvAGt/0X/af7d/kgBoAGsAbX+Vf6t/qX+lf6R/rH+qf6x/qn+sf6p/2n+Hf5l/lH+ZAGh/kX+rf6V/p3+jf6x/p3+k',
    1249128, 'f7EAbgBuf5V/k3+ZAG5/2n+RAGwAZABrf5d/mQBmf5EAawBs', 3383047758, 'f6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qX+pf6l/qn+qf6p/qn+qf6p/qn+qf6o=',
    937306024, 1223002223, 1247604, 1247604, 'yXPJY8ljyWM=', 3808811496, 2322940469, 'f6l/qn+sf6p/rH+q',
    507438676, 1183596, 4263566231, 1015334571, 194137931, 1246080, 3150463209, 2813048779,
    2757439637, 49207, 49367, 1249128, 'xRPKE8UDyjPKM8VD', 'f5UAbH+tf4V/h3+uf5UAbA==', 2669798110, '',
    'ytPF88VDyRPJAw==', '', 53301, 49367, 1269740074, 49207, 1249128, 388493917,
    'pa', 16610, 'yjPFQ8mzyzPLEw==', 2567088320, 49367, 1249128, 487850191, 3272764293,
    752693457, 1249128, 3824370889, 3522888327, 49207, 'PUD', 4236115781, 1249128,
    3385030289, 3879556876, 3591667810, 1247604, 8304, 1415162902, 49367, 456095000,
    'f5IAZgBmAGoAZ3+gf6t/qwBif6x/lwBrAG0=', 2408762855, 2065173748, 'yjPKA8jjyWPJc8lzynPJA8mzyTPKE8XDygPJs8kjyPPKE8jDybPKA8lzyQPJE8mzygPJI8jTygPJI8jTyRPJM8jzyNPI88lj',
    49367, 3013372099, -1676949, 3377717700, 2508865046, 49207, 'vZ', 'f4h/uX+1f7l/lABjf4p/owBpAGt/iX+if7l/uX+Kf6V/gX+hAG1/g3+5f7l/jX+Cf4R/j3+1f4N/uX+5f41/sn+4f4YAagBhf5h/qH+hf6p/jgBjf41/sH+OAGx/sQBmf41/hn+wAGt/mH+nf5d/pX+Bf5N/sQBif4N/qH+If5J/ln+zf7UAZn+Xf6h/oQBlf5gAbX+EAGF/jn+Cf4gAZH+Bf4J/jH+qf4B/gn+wf5Z/g3+of4gAan+Xf5B/qn+Rf5h/sn+IAGF/sQBuf6oAZ3+xf7N/kn+qf5h/gwBif5h/gH+zAG4AYX+Kf4d/sABnf5Z/sn+xf5F/gn+VAG9/t3+Bf4h/jQBlf5kAbX+Ef6p/gABsf4QAbn+Yf7d/qQBgf5Z/sgBuAGd/gH+Hf6kAYX+Yf6h/oX+qf5F/k3+Yf4B/uH+4f6oAZX+ZAG1/hH+qf4AAbH+EAG5/mH+3f6kAYH+Wf7IAbgBnf4B/h3+pAGF/mH+of6F/qn+xf7d/pQBpf5gAbX+AAGl/i3+DAGoAYH+Nf7Z/j3+pf7l/iX+BAGV/l3+FAGp/hX+Hf7V/p3+Qf7l/hH+1f7l/gn+Tf4Z/sH+5f5MAaH+Ff7l/pABmf7h/uQBvf6YAYX+Gf5UAYn+Qf7gAbH+If7B/gX+Tf7l/s3+Wf7UAbn+Rf7l/uX+Af6p/h3+Df7F/uX+4AGx/iH+wf4F/k3+5f7N/ln+1AG5/kX+5f7l/gH+qf4d/g3+xf7l/jn+5f6YAaH+Qf4l/uX+zf5Z/tQBuf5F/uX+0f4R/on+yf4B/pn+4f7l/uX+3f4l/tn+kf6Z/i3+5f4l/uX+5AG9/uX+vAGV/tn+RAGwAZX+Yf6l/mX+MAGUAa3+Ff7Z/ggBlAGgAa3+Nf7l/sn+1f5B/sn+xf4B/uX+Df6p/lQBgf7EAb3+4AGJ/sQBiAGF/s3+Hf41/kX+5f7l/iX+1f5h/ogBtf4N/qwBnf5B/g3+oAGp/uH+lAGJ/q3+Tf7V/mH+xf4x/tX+Bf4l/vX+9',
    'AGoAb3+bf7kAZH+If5l/o3+hf5h/sgBhf7B/h3+Bf4d/iX+yAGx/iABqf5d/hABmAGAAYQBif5UAZn+HAGR/tH+VAGgAYg==',
    49367, 2636584998, 43248, 1150352718, 'f6l/o3+hf6Z/qH+pf6l/pn+of6h/qn+hf6I=', 2771746893, False, 49367,
    1198837346, 'f5d/mH+Zf6V/lH+kf6d/mQ==', 'yhPI48kjyhPI88kzyPPKIw==', 577699099, 3070229989, 'yRPJU8lzyVPJc8jzyNPJY8mjzmPI08iDyWPJY8iDyWPJY85jyHPLsw==',
    16909571, 49367, 442002601, 3035568173, 1340281397, 'm', 2963999779, 2613459878,
    1247604, 3617085942, 2385394473, 49247, 2753784766, 3519538413, -891113582, 3543254481,
    339485169, 1418962653, 1239984, [2484485448, 1042940604], '', 49367, 2860529006, 3508813611,
    2866640979, 'f6p/rH+qf6x/qn+sf6o=', 2562701757, 1269040138, '116.96.44.23', 49247, 1247604, 1249128,
    1249128, 49367, False, 1569858398, [50760149, 1161382465], 'f6h/lX+Yf5V/qn+Yf5R/oQ==', 541121377,
    1212552, 1448084201, 49367, 2401801926, 2200278408, False, 3222704043, 3773292932,
    1247604, 'yRPJM8kDyMPJM8UDxNPI08WDyhM=', 57567, 49207, 49367, 3651236754, 'f7l/jH+zf45/tX/af9J/jH+Ef7F/tn+xf7l/rn/af4x/hH+xf7Z/sX+5f9p/s3+Vf7QAawBof5d/lX/af7N/hn/af6N/qX+qf9p/0n+qAGJ/qn+qf6p/qn+pf6h/on+4f9F/2n+2f5EAaH+Vf5cAZn+nf7Z/qX+pf9oAZABnf5t/pX+bf6p/2gBqAGd/m3+lf5t/qn+uf9p/tn+nf7Z/qX+pf9E=',
    49367, 2104516869, 1247604, 1730102250, 2990244323, 2664928827, False, 725162241,
    1221696, 1754461498, 1249128, 1228285066, 1249128, 3499362831, 1223220, 3026675725,
    3180856003, 'AGoAaABrf5h/mX+YAG4AYQ==', 2710842118, 1777725986, -151425, 49335, 3526367965, 49367,
    25210520, 3793574343, 1410602429, 'f5Z/lH+Uf5V/on+kf6V/oQ==', 2685099295, 1703389621, 4140223554,
    49167, 3168339212, 2824995466, 35224, 1720361069, 2714670582, 2989302407, 3495639297,
    1241508, 1153964434, 1759481890, 648459434, 1249128, 1352018333, 4014164625, 506447925,
    2420722816, [2003887619, 546179288], 1115016, 1249128, 3258321204, 49367, 2357398804, 109746612,
    1249128, 373432700, 3353847326, 'yHPLQ8vTy6PIM85jyePLQ8rDy/PII8vzyHPJo85jy0PKw8vzyCPL88hzzmPL08ozy8PFU8UDyhPKM85jy9PLI85jyNPJc8ljzmPJ48ljxOPJY8ljyWPJY8lzyQPI48gDyfPOY8gjxfPFA8ozyhPFI8kTyCPJc8lzzmPEw8UTylPJM8pTyWPOY8VjxRPKU8kzylPJY8mjzmPII8kTyCPJc8lzyfM=',
    49367, 1247604, 3185699516, 2481715986, 2589701076, 49367, 1249128, 2646851,
    1249128, 'f6t/q3/af7F/jH+xf4Z/sX+5f45/2n+yf45/h3+Of9p/uH+1f7N/sX+Mf/B/8H/XAGoAaH+Zf5MAbX+Zf9oAY3+ZAGgAbH+RAGx/k3/Sf9p/ln+RAGd/mX+YAG5/lX+gf9p/p3+qf6J/qX/af6d/pX+lf6R/2n+nf6V/pX+jf9p/p3+lf6N/qX/af9F/8H/Xf5F/lH+Wf5V/lH/af7l/jH+zf45/tX+bf7V/jH+5f7h/jn+1f5t/jn+Lf4t/in+bf7R/jn+5f4Z/hn+1f4x/8H/Xf5Z/lX+Uf5EAbH+Vf9p/jn+Lf4t/in/af58AbgBr',
    37942, 960505625, 830333183, 2055888913, 'xZPKM8VjxaPKM8UD', 49367, [809700834, 1332621334], -30331197,
    497796, 49367, 49367, 1249128, 3682664177, 4000743652, 1166189218, 49367,
    1247604, 2316390240, 102027060, 1249128, 49207, 2747267908, [2993435683, 2478882644], 3492168537,
    49207, 3433538238, 'iqm', -2070157953, 1249128, 1247604, 2569107045, 49367,
    49367, 229501842, 552881220, 3694156295, 147635309, 2988239072, 57567, 2778636531,
    2684168948, 1127208, 1908689276, 3086270511, 49367, 3774232924, 3241281329, 7770,
    False, '3ab02303', 'r', 4236023230, 2281601290, 2275010798, 2926395870, 49367,
    -867478791, 1942074822, 49367, 49367, 3222166620, -4456725, 3501872715, 8443,
    3029370148, 49367, 'f6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6p/qn+qf6o=',
    1247604, True, 1249128, -867478791, 779585794, 1249128, 1977001786, 1662080932,
    49367, 2208935216, 1233888, [803155918, 3703488902], 1249128, 2694906050, 1198836, 773374379,
    4231156923, 49207, 1895673043, 'xbPKc8TzygPKMw==', 4063927623, 1262053057, 49271, 868611217,
    'y9PFU8VTxdPFo8ozzmPL88VDyhPJQw==', 49207, 2516876253, 49367, 'f6R/pg==', 421285308, 2456057036, 2444668932,
    1249128, 2654676429, 1604428744, 1249128, 3233484841, 1249128, 'yuPJQ85jy/PFI87xxRPOY8TTxePKc8UjzvHFE85jxePKc8VjxWPKM8VDxfPFQ8XTzmPJU85jyuM=',
    1249128, 'xaPKc8VDyiPFE8oTynPFY8ozybPFY8UDxfPFs8pzxQPE8w==', 3275319448, False, 1249128, 788300759,
    3530785482, 49367, 'fHMf', 1818065140, 905179554, 2960999605, 386109474, 53958,
    1249128, 1447061983, 27216, 'yMPJE8jzyQPJY8jDyOPI88kD', 'yBPKc8VDxUPFU8UjzmPFA8ozynPKI85jxWPFA8VTxWPKM8UDxSPF88ozxRPOY8VTxcPOY8UzxUPKI8ozxcPF88VDyjPKI85jyePFA8ozynPKI8XzxUPF085jydPKA8nTyfM=',
    957855224, 'yiPFI8WjxRPJs8UTyhPFI8VjyZPFM8ojxWM=', 3370223622, 3063675484, 2478490668, 2365130266,
    49367, 3985983526, 651293982, 4223062685, 1468359466, 2476975235, 'f4x/uQ==', 'N',
    1249128, 1494673906, 2494740225, 345540095, 844215408, 455124657, 1899873474, 732595904,
    1249128, 1249128, -867478791, 3878097659, 1241508, '', 809858652, 49207,
    1232364, 'f6d/pn+Yf6Z/pX+mf5l/ow==', 4211479847, 1249128, 49367, 1060597964, [118305367, 4081852244],
    4110831658, 'eHy', '', 1229316, 2871680845, [331280046, 3096912239], 2269660135, 19767,
    True, 965210819, 1079060201, 2106057155, 1455535503, 454058617, -396789, 441626791,
    [1041274657, 1788463454], 1241508, 2618767308, 235615803, 49367, 1213364531, 3164080113, 'AGN/lX+YAG9/kQBm',
    131056887, 49207, 49367, 797328557, 'yhPKc8jzySPJM8oDyWPKMw==', 3134270727, 16171, 2818614165,
    1144523680, 1249128, 3004379848, 'yQPJY8ljyRPJY8lzyWPI0w==', 49207, False, 1249128, 4204505546,
    3930316357, True, 2177354382, 'AGR/kQBnf5F/mABuf5U=', 68375734, 1247604, 8316, 49367,
    True, 2166270497, 1334497740, 'xWPFA8VTygPKc8oDxaPE8w==', 49207, 'y7PFU8SDxfPFo8WjynPJU8kzyUPJY85jyePK08XzxUPKI8VTxNPFE85jy0PLI85jyXPJY8lDyWPIk85jytPF88VDyMPJI8iTzmPE48jDySPJ885jyHPFY8VjxaPKM8rTyjPKA8uTxfPFI8lTyTPJE8jTyUPJE8jDzmPJ48uTy+PLI8uzy6PJo85jxaPF88WTyjPOY8vTyjPKE8WTxVPJ885jyBPF48UDxVPFs8ozyVPJc8kzyMPJQ8ljyUPJY8lDyWPOY8sTynPFw8pzxQPF88lTyTPJE8jTyUPJE8jD',
    'f58Af3/Yf5gAaH+ZAGx/ln/Yf6B/2H+MAGsAZn+gf7l/rX+4AGh/mQBsf5Z/2H+uf9gAZH+VAGgAZ3+RAGsAbH/Yf6B/2H+if6x/qn+sf6p/rH+qf9gAfX+uAH9/2H+YAGh/mQBsf5Z/2H+gf9h/t3+SAGgAawBtf5EAZQBtf9h/rn/YAGR/lQBoAGd/kQBrAGx/2H+gf9h/qX+lf6R/rH+qf6x/on+qf6N/on+sf6J/qX/YAH1/rgB/f9h/mABof5kAbH+Wf9h/oH/Yf7MAawBrf5MAbn+Vf9p/t3+SAGgAawBtf5V/2H+uf9gAZH+VAGgAZ3+RAGsAbH/Yf6B/2H+pf6V/pH+sf6p/rH+if6p/o3+if6x/on+pf9gAfX+d',
    49367, 170056699, [2622493776, 714011466], False, 881788825, 1281525291, 49367, 593993784,
    'YaWU', 'xePFI8UjxWPFE8iD', 3598731646, False, 3126989369, 49367, 'AGx/mQBkf5F/k3+ZAGZ/lQ==', 1282940801,
    1183596, 1947402827, 3912703323, 2909864661, 791715133, 1249128, 1249128, 3836343812,
    617992957, 1247604, 49207, 49335, 2548760351, 1247604, 3374067190, 'xbPFU8UzxRPKM8TTxePKM8ozxaM=',
    49367, 3882135711, 'f4YAYQBqf5V/tQBoAGgAawBof6B/2n+3AGF/lwBuf5F/l3/af5t/mwBqAGgAawBmAGt/m3+bf9oAZH+ZAG4AZX+V',
    3103269622, 14732, 96903793, 3986648318, 2089290728, 45939, 49367, 3890265972,
    795150609, -2070214341, 611183256, 1249128, 'Wp', 3019758303, 'xUPEw8XzyiPF88pz', 'ywk',
    1249128, 2509132627, 49367, 4175208, 4034438534, 1247604, 2871425146, 983952,
    49367, 1191770468, 'R', 4156090977, '', '', 1805231212, 81916576,
    111277703, 'f7MAawBrf5MAbn+Vf9p/t3+SAGgAawBtf5U=', 49207, 2754559183, 1243032, 'lkL', 'y7PKc8TjxfPFs8UzxbPOY8oTynPFo8WjzmPFE8UjynPKE8WTzmPFE8XzxIPKM85jyjPE48oTyjPKM8ojyjPKIw==',
    'xOPJQ8oTxVPFsw==', 49367, 3325805734, -1426306219, 18122, 3754286036, 1249128, 1249128,
    1249128, -1682640279, 2274038867, 3228172163, 49367, 2498377706, 3176493010, 49367,
    1247604, 3324581496, 314042413, 1357547473, 49367, 6911, 2040172037, 2821914553,
    3917962238, 53462, 2759948312, 3055263586, 1247604, 2903536607, 49207, 1090950389,
    'hvyv', 3408664239, 'ypPEk84DygPFA8pzxUPKI84DyIPOA8tDxVPFI8iDyHPJs8gDxQPKc8VDyiPOA8mjzgPEw8ozxQPFE8XzxVPFQ84DyIPOA8jjzgPEs8mjxJPOA8oDxQPKc8VDyiPOA8iDzgPIE8XjxQPFU8WzxfPFM8WzzgPJo84DxMPKM8UDxRPF88VTxUPOA8iDzgPJc8kzyMPOA8SzyaPEk84DygPFA8pzxUPKI84DyIPOA8vTxVPFU8XTxaPKM85jyBPF48UDxVPFs8ozzgPJo84DxMPKM8UDxRPF88VTxUPOA8iDzgPJc8kzyMPOA8SzyrM=',
    3800394628, 1249128, 100625304, 'yVM=', 213260528, 49367, 703509466, 954621273,
    49367, 1249128, 689783349, 2863153392, -2070388077, 664435009, -1676949, 3950335888,
    2225023984, 'yhPKE8kDyTPKM8kDyWPI4w==', 1249128, 1326385072, 1283096736, 2832755034, True, 1249128,
    34528, 3305907681, 855617573, 1249128, 2797666837, 1241508, 804811942, -1062777,
    190446216, 3338004831, 2167852095, 1236936, 1249128, 'yXPJM8jDyUPJY8lDyOPJY8jTyOPJQ8jjyXM=', -2972349,
    1528477753, 3788265304, 62236, 55800, 882714469, 59146, 'f6l/mX+m', 128,
    88, 13718, 'f5Z/o3+nf6J/o3+Y', 7726077, 'f6c=', -523567265, 1998263746, '2LqqOw==',
    '2OTkBA==', 'uKqqOw==', 'oaGhoQ==', 'SUuhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'uKqqKg==', 'oaGhoQ==',
    '+Fdnhw==', '2OTkBA==', 'oaGhoQ==', 'uKqqOw==', '2OTkBA==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==',
    '+Kqqqg==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==',
    'oaGhoQ==', 'uKqqOw==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==',
    'uKqqOw==', 'oaGhoQ==', 'uKqqOw==', 'uKqqOw==', 'uKqqOw==', 'oaGhoQ==', '2OTkBA==', 'oaGhoQ==',
    'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'uKqqOw==', 'oaGhoQ==',
    '2Lqqqg==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==',
    'uKqqKg==', 'KfehoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'oaGhoQ==', 'ifEiyg==', '2OTkBA==',
    'SbuhoQ==', '+PTkBA==', 'iQSVLQ==', 'iRWVLQ==', 'ieQtLQ==', 'iVNnZw==', 'iVXfZw==', 'iY+hoQ==',
    'iZ6hoQ==', 'iY+qyg==', 'ib2hoQ==', 'iVPvZw==', 'iTNsBA==', 'ia9nZw==', 'iSG6yg==', 'iXMpoQ==',
    'iUAdLQ==', 'iZKqyg==', 'icSqyg==', 'iVFsBA==',
)


# ===========================================================================
# 6. BỘ MÃ HOÁ MẢNG METRICS & TẠO TOKEN HOÀN CHỈNH (CASTLE TOKEN GENERATOR)
# ===========================================================================

class CastleTokenGenerator:
    """
    Nhận các field ở dạng chưa mã hoá (human-readable) hoặc ClientProfile,
    tự động mã hoá lại theo từng phiên bản (V1 / V2 / V3), serialize, nén
    raw deflate, đóng gói header bảo mật 24 byte và stream cipher thành
    Castle token hợp lệ.
    """

    VERSION_PREFIX = {
        1: "uq1seNrd",
        2: "cNz8rPYH",
        3: "WcmFKZlD",
        4: "EZK-f_Qb",
    }

    def __init__(self, workspace_dir: Optional[str] = None):
        self.field_generator = CastleFieldGenerator(workspace_dir=workspace_dir)

    def encode_metrics(
        self,
        unencrypted_metrics: List[Any],
        version: Union[int, str] = 3,
        encode_v1_ast: bool = False,
    ) -> List[Any]:
        """
        Chuyển đổi mảng metrics từ dạng chưa mã hoá (plaintext / human-readable)
        sang dạng mã hoá cấp trường ($) trước khi serialize:
          - V1: Đóng gói header OS ($[59]), Fd() Float32 cho timing (668..748),
                cập nhật 10 trường tự kiểm tra chéo En()/Dn() (658..667),
                và (tuỳ chọn) áp dụng AST cipher (Pn/Mn/On/pair_hash).
          - V2: Mã hoá chuỗi bằng lr(), mã hoá timing 683..767 bằng kd() Float32,
                giữ nguyên các field chưa mã hoá (int, bool, null, hash pair).
          - V3: Áp dụng đúng cipher cấp trường của từng chỉ số trong mẫu V3 thực tế:
                + V3_GN_STR_INDICES (37 trường): Mã hoá bằng Gn()
                + V3_KN_STR_INDICES (32 trường): Mã hoá bằng Kn()
                + V3_RAW_STR_INDICES (34 trường): Giữ nguyên raw string (đóng gói nhị phân cho 53, 78)
                + V3_INT_A_PROFILE_INDICES & V3_INT_B_PROFILE_INDICES: Mã hoá bằng Group A / B Integer Cipher
                + 687..771: Mã hoá bằng Qd() Float32
        """
        ver = self.field_generator._normalize_version(version)
        encoded = list(unencrypted_metrics)

        if ver == 4:
            for i, val in enumerate(encoded):
                if 691 <= i <= 775 and isinstance(val, (int, float)) and not isinstance(val, bool):
                    if val not in (161, 165, 173):
                        encoded[i] = encode_wd_float32(float(val))
                elif i == 53 and isinstance(val, str):
                    encoded[i] = encode_v3_os_field(val)
                elif i == 78 and isinstance(val, str):
                    encoded[i] = encode_v3_shader_field(val)
                elif i in V3_INT_A_PROFILE_INDICES and isinstance(val, int) and not isinstance(val, bool):
                    if decode_v3_int_a(val) is None:
                        encoded[i] = encode_v3_int_a(val)
                elif i in V3_INT_B_PROFILE_INDICES and isinstance(val, int) and not isinstance(val, bool):
                    if decode_v3_int_b(val) is None:
                        encoded[i] = encode_v3_int_b(val)
                elif i in V3_RAW_STR_INDICES:
                    encoded[i] = val
                elif isinstance(val, str) and val:
                    if decode_nr(val) is None:
                        encoded[i] = encode_nr(val)
            return encoded

        if ver == 3:
            for i, val in enumerate(encoded):
                if 687 <= i <= 771 and isinstance(val, (int, float)) and not isinstance(val, bool):
                    if val not in (161, 165, 173):
                        encoded[i] = encode_qd_float32(float(val))
                elif i == 53 and isinstance(val, str):
                    encoded[i] = encode_v3_os_field(val)
                elif i == 78 and isinstance(val, str):
                    encoded[i] = encode_v3_shader_field(val)
                elif i in V3_INT_A_PROFILE_INDICES and isinstance(val, int) and not isinstance(val, bool):
                    if decode_v3_int_a(val) is None:
                        encoded[i] = encode_v3_int_a(val)
                elif i in V3_INT_B_PROFILE_INDICES and isinstance(val, int) and not isinstance(val, bool):
                    if decode_v3_int_b(val) is None:
                        encoded[i] = encode_v3_int_b(val)
                elif i in V3_GN_STR_INDICES and isinstance(val, str) and val:
                    if not self._is_already_gn_encoded(val):
                        encoded[i] = encode_gn(val)
                elif i in V3_KN_STR_INDICES and isinstance(val, str) and val:
                    if not self._is_already_kn_encoded(val):
                        encoded[i] = encode_kn(val)
                elif i in V3_RAW_STR_INDICES:
                    # Giữ nguyên raw string (ví dụ: 29 browser_ver_detail, 212 client_ip, 445 cdp_code...)
                    encoded[i] = val
                elif isinstance(val, str) and val:
                    if not (is_valid_base64_blob(val) and not self._looks_like_plaintext_v3(i, val)):
                        encoded[i] = encode_gn(val)
            return encoded

        if ver == 2:
            for i, val in enumerate(encoded):
                if 683 <= i <= 767 and isinstance(val, (int, float)) and not isinstance(val, bool):
                    if val not in (161, 165, 173):
                        encoded[i] = encode_kd_float32(float(val))
                elif isinstance(val, str) and val:
                    if not (is_valid_base64_blob(val) and not self._looks_like_plaintext_v2(i, val)):
                        encoded[i] = encode_lr(val)
            return encoded

        # V1 (uq1seNrd)
        if len(encoded) > 59 and isinstance(encoded[59], str):
            encoded[59] = encode_v1_os_field(encoded[59])

        if encode_v1_ast:
            spec = self.field_generator.get_v1_cipher_spec()
            for i, val in enumerate(encoded):
                if i not in spec or val is None or val in (161, 165, 173):
                    continue
                ctype = spec[i]["cipher"]
                if ctype == "pn" and isinstance(val, str) and not is_valid_base64_blob(val):
                    encoded[i] = encode_pn(val)
                elif ctype == "mn" and isinstance(val, str) and not is_valid_base64_blob(val):
                    encoded[i] = encode_mn(val)
                elif ctype == "on" and isinstance(val, int) and not isinstance(val, bool):
                    encoded[i] = encode_on(val)
                elif ctype == "fd" and isinstance(val, (int, float)) and not isinstance(val, bool):
                    encoded[i] = encode_fd_float32(float(val))
                elif ctype == "pair_or_int" and isinstance(val, (int, float)) and not isinstance(val, bool):
                    encoded[i] = encode_v1_pair_or_int(val, *spec[i]["consts"])
            apply_v1_self_consistency_hashes(encoded)
        else:
            # Mặc định tương thích trực tiếp với PureCastleDecoder cho V1
            for i in range(668, min(749, len(encoded))):
                val = encoded[i]
                if isinstance(val, float):
                    encoded[i] = encode_fd_float32(val)

        return encoded

    @staticmethod
    def _is_valid_text_chars(decoded: Optional[str]) -> bool:
        if not decoded:
            return False
        for ch in decoded:
            c = ord(ch)
            if not ((32 <= c <= 126) or c in (9, 10, 13) or (0x00A0 <= c <= 0x024F) or (0x2000 <= c <= 0x206F)):
                return False
        return True

    @classmethod
    def _is_already_gn_encoded(cls, s: str) -> bool:
        """Kiểm tra xem chuỗi đã ở dạng Base64 mã hoá bằng Gn() hay chưa."""
        if not is_valid_base64_blob(s):
            return False
        return cls._is_valid_text_chars(decode_gn(s))

    @classmethod
    def _is_already_kn_encoded(cls, s: str) -> bool:
        """Kiểm tra xem chuỗi đã ở dạng Base64 mã hoá bằng Kn() hay chưa."""
        if not is_valid_base64_blob(s):
            return False
        return cls._is_valid_text_chars(decode_kn(s))

    @staticmethod
    def _looks_like_plaintext_v2(idx: int, s: str) -> bool:
        """Nhận diện chuỗi plaintext (kể cả chuỗi 4 ký tự như 'x.com', 'Win32', 'true') cần mã hoá lr()."""
        if idx in METRIC_INFO_V2:
            return True
        return not is_valid_base64_blob(s)

    @staticmethod
    def _looks_like_plaintext_v3(idx: int, s: str) -> bool:
        """Nhận diện chuỗi plaintext cần mã hoá Gn() trong V3."""
        if idx in METRIC_INFO_V3:
            return True
        return not is_valid_base64_blob(s)

    def generate_token(
        self,
        version: Union[int, str] = 3,
        profile: Optional[ClientProfile] = None,
        unencrypted_metrics: Optional[List[Any]] = None,
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        timestamp_ms: Optional[int] = None,
        is_bot: bool = False,
        encode_v1_ast: bool = False,
    ) -> Dict[str, Any]:
        """
        Tạo Castle token hoàn chỉnh từ các field chưa mã hoá hoặc từ ClientProfile.
        Trả về dict chứa token, thông tin header, mảng chưa mã hoá và mảng đã mã hoá.
        """
        ver = self.field_generator._normalize_version(version)
        prefix = self.VERSION_PREFIX[ver]
        prof = profile or ClientProfile()

        if timestamp_ms is None:
            timestamp_ms = prof.timestamp_ms or int(time.time() * 1000)
        ts_str = str(int(timestamp_ms)).zfill(13)[:13]

        # 1. Chuẩn bị mảng metrics chưa mã hoá
        if unencrypted_metrics is not None:
            clean_metrics = list(unencrypted_metrics)
            if overrides:
                info_map = (
                    METRIC_INFO_V4 if ver == 4 else (METRIC_INFO_V3 if ver == 3 else (METRIC_INFO_V2 if ver == 2 else METRIC_LABELS))
                )
                slug_to_idx = {
                    (v[0] if isinstance(v, tuple) else v): k for k, v in info_map.items()
                }
                for k, v in overrides.items():
                    if isinstance(k, int) and 0 <= k < len(clean_metrics):
                        clean_metrics[k] = v
                    elif isinstance(k, str):
                        if k.isdigit() and 0 <= int(k) < len(clean_metrics):
                            clean_metrics[int(k)] = v
                        elif k in slug_to_idx:
                            clean_metrics[slug_to_idx[k]] = v
        else:
            clean_metrics = self.field_generator.generate_unencrypted_metrics(
                version=ver, profile=prof, overrides=overrides, is_bot=is_bot
            )

        # 2. Mã hoá cấp trường (per-field encryption)
        encoded_metrics = self.encode_metrics(
            clean_metrics, version=ver, encode_v1_ast=encode_v1_ast
        )

        # 3. Tuần tự hoá (Binary Protocol Serializer) & Nén (Raw Deflate)
        serialized_bytes = serialize_castle_payload(encoded_metrics)
        compressed_bytes = compress_castle_payload(serialized_bytes)

        # 4. Tạo 24-byte Security Header + Mã hoá luồng (Stream Cipher)
        header_and_ciphertext = encrypt_with_security_header(
            compressed_bytes, ts_str, version=ver
        )
        auth_header = header_and_ciphertext[:24]
        ciphertext = header_and_ciphertext[24:]
        seg1_len = struct.unpack(">I", auth_header[0:4])[0]
        seg2_len = struct.unpack(">I", auth_header[4:8])[0]
        checksum_hex = auth_header[8:24].hex()

        # 5. Mã hoá khóa thời gian 13 chữ số (Timestamp Key)
        if ver == 4:
            key_b64 = encode_nr(ts_str)
        elif ver == 3:
            key_b64 = encode_gn(ts_str)
        elif ver == 2:
            key_b64 = encode_lr(ts_str)
        else:
            key_b64 = encode_pn(ts_str)
        key_bytes = key_b64.encode("latin1")
        key_len = len(key_bytes)

        # 6. Đóng gói khung nhị phân: [keyLen_lo, keyLen_hi, ...keyBytes, header(24), ciphertext]
        packet = bytearray(2 + key_len + len(header_and_ciphertext))
        packet[0] = key_len & 0xFF
        packet[1] = (key_len >> 8) & 0xFF
        packet[2 : 2 + key_len] = key_bytes
        packet[2 + key_len :] = header_and_ciphertext

        token_str = f"{prefix}|{base64.b64encode(bytes(packet)).decode('ascii')}"

        return {
            "token": token_str,
            "version": ver,
            "prefix": prefix,
            "timestamp_ms": int(ts_str),
            "timestamp_key_b64": key_b64,
            "metrics_count": len(clean_metrics),
            "serialized_bytes": len(serialized_bytes),
            "compressed_bytes": len(compressed_bytes),
            "ciphertext_bytes": len(ciphertext),
            "security_header": {
                "segment_1_bytes": seg1_len,
                "segment_2_bytes": seg2_len,
                "signature_hash": checksum_hex,
            },
            "unencrypted_metrics": clean_metrics,
            "encoded_metrics": encoded_metrics,
        }

    def from_decoded_json(
        self,
        decoded_data: Union[Dict[str, Any], List[Any]],
        overrides: Optional[Dict[Union[int, str], Any]] = None,
        timestamp_ms: Optional[int] = None,
        version: Optional[Union[int, str]] = None,
    ) -> Dict[str, Any]:
        """
        Tái tạo Castle token hợp lệ từ dữ liệu JSON đã giải mã (output của decode_token.py
        hoặc castle_decoder.py), cho phép chỉnh sửa bất kỳ field chưa mã hoá nào.
        """
        if isinstance(decoded_data, list):
            clean_metrics = list(decoded_data)
            ver = version or (4 if len(clean_metrics) >= 776 else (3 if len(clean_metrics) >= 772 else (2 if len(clean_metrics) >= 765 else 1)))
            ts = timestamp_ms
        elif isinstance(decoded_data, dict):
            clean_metrics = (
                decoded_data.get("all_metrics_cleaned")
                or decoded_data.get("raw_metrics_array")
                or decoded_data.get("unencrypted_metrics")
            )
            if clean_metrics is None and "formatted_metrics" in decoded_data:
                clean_metrics = [m.get("raw") for m in decoded_data["formatted_metrics"]]
            if clean_metrics is None:
                raise ValueError("JSON đầu vào không chứa mảng metrics ('all_metrics_cleaned' hoặc 'raw_metrics_array').")
            ver = version or decoded_data.get("token_version") or (
                4 if len(clean_metrics) >= 776 else (3 if len(clean_metrics) >= 772 else (2 if len(clean_metrics) >= 765 else 1))
            )
            if timestamp_ms is None:
                ts = (
                    decoded_data.get("session_time", {}).get("epoch_ms")
                    or decoded_data.get("timestamp", {}).get("raw_timestamp_ms")
                    or decoded_data.get("timestamp_ms")
                )
            else:
                ts = timestamp_ms
        else:
            raise TypeError("decoded_data phải là dict hoặc list.")

        return self.generate_token(
            version=ver,
            unencrypted_metrics=clean_metrics,
            overrides=overrides,
            timestamp_ms=ts,
        )


# ===========================================================================
# 7. GIAO DIỆN DÒNG LỆNH (CLI)
# ===========================================================================

def _parse_override_value(raw_val: str) -> Any:
    """Chuyển đổi giá trị truyền qua CLI (--set key=val) sang kiểu dữ liệu Python tương ứng."""
    low = raw_val.strip().lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none"):
        return None
    if re.match(r"^-?\d+$", raw_val.strip()):
        return int(raw_val.strip())
    if re.match(r"^-?\d+\.\d+$", raw_val.strip()):
        return float(raw_val.strip())
    if (raw_val.startswith("[") and raw_val.endswith("]")) or (
        raw_val.startswith("{") and raw_val.endswith("}")
    ):
        try:
            return json.loads(raw_val)
        except Exception:
            pass
    return raw_val


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Castle Anti-Bot Unencrypted Field & Token Generator (V1 / V2 / V3)"
    )
    parser.add_argument(
        "--version", "-v", default="v4", choices=["v1", "v2", "v3", "v4", "1", "2", "3", "4"],
        help="Phiên bản Castle token cần sinh: v1 (uq1seNrd), v2 (cNz8rPYH), v3 (WcmFKZlD), v4 (EZK-f_Qb). Mặc định: v4"
    )
    parser.add_argument("--ip", help="Địa chỉ IP client (ví dụ: 40.221.213.80)")
    parser.add_argument("--os", dest="os_name", help="Tên hệ điều hành (ví dụ: Windows, Macintosh, Linux)")
    parser.add_argument("--ua", help="Chuỗi User-Agent trình duyệt")
    parser.add_argument("--browser-version", help="Phiên bản trình duyệt (ví dụ: 131.0.0.0)")
    parser.add_argument("--gpu", help="Tên GPU WebGL renderer")
    parser.add_argument("--tz", help="Múi giờ IANA (ví dụ: Asia/Ho_Chi_Minh, Europe/Istanbul)")
    parser.add_argument("--locale", help="Ngôn ngữ / Locale (ví dụ: vi-VN, en-US)")
    parser.add_argument("--guid", help="Device UUID / GUID")
    parser.add_argument("--session-id", help="Session ID")
    parser.add_argument("--timestamp", type=int, help="Unix timestamp (ms, 13 chữ số)")
    parser.add_argument("--bot", action="store_true", help="Bật các cờ bot/automation để kiểm thử phát hiện bot")
    parser.add_argument(
        "--set", "-s", action="append", default=[],
        help="Ghi đè giá trị field chưa mã hoá theo slug hoặc index (ví dụ: -s client_ip=1.2.3.4 -s 43=false)"
    )
    parser.add_argument(
        "--from-json", "-f",
        help="Đường dẫn file JSON đã decode (hoặc mảng metrics chưa mã hoá) để mã hoá lại thành token"
    )
    parser.add_argument(
        "--dump-unencrypted", "-u",
        help="Lưu mảng các field chưa mã hoá (human-readable JSON) ra file"
    )
    parser.add_argument(
        "--output", "-o",
        help="Lưu toàn bộ kết quả (token + metadata + unencrypted fields) ra file JSON"
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Tự động giải mã lại token vừa sinh bằng PureCastleDecoder để kiểm tra toàn vẹn"
    )
    parser.add_argument(
        "--token-only", "-t", action="store_true",
        help="Chỉ in chuỗi Castle token ra stdout"
    )

    args = parser.parse_args()

    profile = ClientProfile()
    if args.ip:
        profile.ip_address = args.ip
    if args.os_name:
        profile.operating_system = args.os_name
    if args.ua:
        profile.user_agent = args.ua
    if args.browser_version:
        profile.browser_version = args.browser_version
    if args.gpu:
        profile.gpu_renderer = args.gpu
    if args.tz:
        profile.timezone = args.tz
    if args.locale:
        profile.locale = args.locale
        profile.language = args.locale
    if args.guid:
        profile.device_guid = args.guid
    if args.session_id:
        profile.session_id = args.session_id
    if args.timestamp:
        profile.timestamp_ms = args.timestamp

    overrides: Dict[Union[int, str], Any] = {}
    for item in args.set:
        if "=" not in item:
            raise ValueError(f"Định dạng --set không hợp lệ: '{item}' (cần dạng key=value)")
        k, v = item.split("=", 1)
        overrides[k.strip()] = _parse_override_value(v)

    gen = CastleTokenGenerator()

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as jf:
            data = json.load(jf)
        res = gen.from_decoded_json(
            data,
            overrides=overrides,
            timestamp_ms=args.timestamp,
            version=args.version if "--version" in sys.argv or "-v" in sys.argv else None,
        )
    else:
        res = gen.generate_token(
            version=args.version,
            profile=profile,
            overrides=overrides,
            timestamp_ms=args.timestamp,
            is_bot=args.bot,
        )

    if args.dump_unencrypted:
        with open(args.dump_unencrypted, "w", encoding="utf-8") as uf:
            json.dump(res["unencrypted_metrics"], uf, indent=2, ensure_ascii=False)
        if not args.token_only:
            print(f"[+] Đã lưu {res['metrics_count']} field chưa mã hoá vào: {args.dump_unencrypted}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as of:
            json.dump(res, of, indent=2, ensure_ascii=False)
        if not args.token_only:
            print(f"[+] Đã lưu chi tiết token vào: {args.output}")

    if args.token_only:
        print(res["token"])
        return

    print("=" * 76)
    print(f" CASTLE TOKEN GENERATOR (Version: V{res['version']} / Prefix: {res['prefix']})")
    print("=" * 76)
    print(f" [*] Timestamp (ms)   : {res['timestamp_ms']} (Key B64: {res['timestamp_key_b64']})")
    print(f" [*] Tổng số Metrics  : {res['metrics_count']} fields")
    print(f" [*] Kích thước       : Serialized={res['serialized_bytes']}B -> Deflated={res['compressed_bytes']}B -> Ciphertext={res['ciphertext_bytes']}B")
    print(f" [*] Security Header  : Seg1={res['security_header']['segment_1_bytes']}B, Seg2={res['security_header']['segment_2_bytes']}B")
    print(f" [*] Checksum (16B)   : {res['security_header']['signature_hash']}")
    print("-" * 76)
    print(" [*] GENERATED CASTLE TOKEN:")
    print(res["token"])
    print("=" * 76)

    if args.verify:
        decoder = PureCastleDecoder()
        dec = decoder.decode_token(res["token"])
        print("\n[+] KIỂM TRA GIẢI MÃ NGƯỢC (ROUND-TRIP VERIFICATION):")
        print(f"    - Trạng thái      : {dec['token_status']}")
        print(f"    - Phán quyết      : {dec['security_verdict']} ({dec['security_verdict_tr']})")
        print(f"    - IP giải mã      : {dec['client_profile']['ip_address']}")
        print(f"    - OS / Trình duyệt: {dec['client_profile']['operating_system']} / {dec['client_profile']['browser_version']}")
        print(f"    - Device GUID     : {dec['client_profile']['device_guid']}")
        print(f"    - Tổng số metrics : {dec['total_metrics_count']}")


if __name__ == "__main__":
    main()
