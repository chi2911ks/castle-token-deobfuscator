#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bộ giải mã Protobuf / JP-5 Binary Wire Format
dành cho response nhị phân của https://jf.x.com (x-jf-v: JP-5).
"""

import re
import json
from typing import Any, Dict, List, Optional, Tuple, Union


def _read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Đọc varint 64-bit từ buffer tại vị trí offset. Trả về (value, new_offset)."""
    result = 0
    shift = 0
    pos = offset
    n = len(data)
    while pos < n:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift >= 64:
            raise ValueError("Varint quá dài (> 64 bit)")
    raise ValueError("Unexpected EOF khi đọc varint")


def _is_printable_utf8(raw: bytes) -> Tuple[bool, str]:
    """Kiểm tra xem chuỗi bytes có phải là chuỗi UTF-8 đọc được (human-readable) hay không."""
    if not raw:
        return True, ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False, ""

    for ch in text:
        code = ord(ch)
        if code < 0x20 and ch not in ("\t", "\n", "\r"):
            return False, ""
        if 0x7F <= code <= 0x9F:
            return False, ""
    return True, text


def _strip_len_prefix(s: str) -> str:
    """
    Trong JP-5 binary format, một số chuỗi có byte đầu tiên chính là độ dài của phần chuỗi còn lại
    (ví dụ: '0/onboarding/...' có ord('0') == 48 == len('/onboarding/...')).
    Hàm này tự động loại bỏ byte length-prefix đó nếu khớp.
    """
    if len(s) >= 2 and ord(s[0]) == len(s) - 1:
        return s[1:]
    return s


def decode_protobuf_raw(data: bytes, depth: int = 0, max_depth: int = 12) -> Union[Dict[str, Any], bytes, str]:
    """
    Giải mã đệ quy Protobuf wire format (tương tự `protoc --decode_raw`)
    thành dict Python để có thể in ra JSON dễ đọc.
    """
    if depth > max_depth or not data:
        ok, text = _is_printable_utf8(data)
        return _strip_len_prefix(text) if ok else f"<bytes:{data.hex()}>"

    pos = 0
    n = len(data)
    fields: Dict[str, Any] = {}

    while pos < n:
        try:
            tag, next_pos = _read_varint(data, pos)
        except ValueError:
            break

        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num <= 0 or field_num > 100000 or wire_type not in (0, 1, 2, 5):
            break

        pos = next_pos
        key = str(field_num)

        if wire_type == 0:
            try:
                val, pos = _read_varint(data, pos)
            except ValueError:
                break
        elif wire_type == 1:
            if pos + 8 > n:
                break
            val = int.from_bytes(data[pos : pos + 8], "little")
            pos += 8
        elif wire_type == 5:
            if pos + 4 > n:
                break
            val = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
        elif wire_type == 2:
            try:
                length, pos = _read_varint(data, pos)
            except ValueError:
                break
            if length < 0 or pos + length > n:
                break
            sub_bytes = data[pos : pos + length]
            pos += length

            if length == 0:
                val = ""
            else:
                is_str, text = _is_printable_utf8(sub_bytes)
                sub_msg = None
                if not is_str or (length >= 4 and sub_bytes[0] in (0x08, 0x0A, 0x10, 0x12, 0x1A, 0x22)):
                    sub_msg = _try_decode_submessage(sub_bytes, depth + 1, max_depth)

                if sub_msg is not None:
                    val = sub_msg
                elif is_str:
                    val = _strip_len_prefix(text)
                else:
                    val = f"0x{sub_bytes.hex()}"
        else:
            break

        if key in fields:
            if not isinstance(fields[key], list):
                fields[key] = [fields[key]]
            fields[key].append(val)
        else:
            fields[key] = val

    if pos != n or not fields:
        ok, text = _is_printable_utf8(data)
        return _strip_len_prefix(text) if ok else f"0x{data.hex()}"

    return fields


def _try_decode_submessage(data: bytes, depth: int, max_depth: int) -> Union[Dict[str, Any], None]:
    """Thử parse `data` như một Protobuf message con; trả về None nếu không khớp hoàn toàn."""
    if len(data) < 2:
        return None
    pos = 0
    n = len(data)
    fields: Dict[str, Any] = {}

    while pos < n:
        try:
            tag, next_pos = _read_varint(data, pos)
        except ValueError:
            return None
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num <= 0 or field_num > 10000 or wire_type not in (0, 1, 2, 5):
            return None
        pos = next_pos

        if wire_type == 0:
            try:
                val, pos = _read_varint(data, pos)
            except ValueError:
                return None
        elif wire_type == 1:
            if pos + 8 > n:
                return None
            val = int.from_bytes(data[pos : pos + 8], "little")
            pos += 8
        elif wire_type == 5:
            if pos + 4 > n:
                return None
            val = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
        elif wire_type == 2:
            try:
                length, pos = _read_varint(data, pos)
            except ValueError:
                return None
            if length < 0 or pos + length > n:
                return None
            sub = data[pos : pos + length]
            pos += length
            if length == 0:
                val = ""
            else:
                is_str, text = _is_printable_utf8(sub)
                nested = _try_decode_submessage(sub, depth + 1, max_depth) if depth < max_depth else None
                if nested is not None and (not is_str or not _looks_like_natural_string(text)):
                    val = nested
                elif is_str:
                    val = _strip_len_prefix(text)
                else:
                    val = f"0x{sub.hex()}"

        key = str(field_num)
        if key in fields:
            if not isinstance(fields[key], list):
                fields[key] = [fields[key]]
            fields[key].append(val)
        else:
            fields[key] = val

    return fields if (pos == n and fields) else None


def _looks_like_natural_string(text: str) -> bool:
    if not text:
        return True
    t = _strip_len_prefix(text)
    if t.startswith(("/onboarding/", "http://", "https://", "^[")):
        return True
    valid_chars = sum(1 for c in t if c.isalnum() or c in " _-./:#?=&+@,!'\"()[]^$\\")
    return (valid_chars / len(t)) >= 0.85


def _collect_strings(obj: Any, out: List[str]) -> None:
    if isinstance(obj, str):
        if obj and not obj.startswith("0x"):
            out.append(_strip_len_prefix(obj))
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, out)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out)


def parse_jf_response(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Phân tích toàn diện response nhị phân từ `https://jf.x.com/onboarding/web/...`:
      - Giải mã cấu trúc Protobuf (`protobuf_tree`)
      - Trích xuất nhanh:
        + `session_token`: UUID của session_token (nếu có trong response)
        + `resolved_username`: Username đã được X phân giải (ví dụ từ email -> username)
        + `next_screen_routes`: Các đường dẫn màn hình tiếp theo (`/onboarding/web#/s/...`)
        + `next_action_endpoints`: Các endpoint API tiếp theo (`/onboarding/web/actions/...`)
        + `extracted_uuids`: Các UUID/token định danh phiên hoặc form
        + `readable_strings`: Toàn bộ chuỗi văn bản có nghĩa trong response
    """
    tree = decode_protobuf_raw(raw_bytes)
    strings: List[str] = []
    _collect_strings(tree, strings)

    if not strings:
        strings = [
            _strip_len_prefix(m.group(0).decode("utf-8", errors="ignore"))
            for m in re.finditer(rb"[\x20-\x7e]{4,}", raw_bytes)
        ]

    routes: List[str] = []
    actions: List[str] = []
    uuids: List[str] = []
    clean_strings: List[str] = []

    uuid_re = re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    )
    route_re = re.compile(r"(/onboarding/web#/s/[A-Za-z0-9_\-/]+)")
    action_re = re.compile(r"(/onboarding/web/actions/[A-Za-z0-9_\-/]+)")

    # Tìm trực tiếp session_token và username trong raw_bytes (cấu trúc JP-5: key + len_byte + value)
    raw_latin1 = raw_bytes.decode("latin1")
    session_token: Optional[str] = None
    m_sess = re.search(
        r"session_token[\x00-\xff]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        raw_latin1,
    )
    if m_sess:
        session_token = m_sess.group(1)

    resolved_username: Optional[str] = None
    for idx, s in enumerate(strings):
        if s == "username" and idx + 1 < len(strings):
            cand = strings[idx + 1].strip()
            if cand and cand not in ("Username", "password", "username_or_email"):
                resolved_username = cand
                break

    for s in strings:
        s_strip = _strip_len_prefix(s.strip())
        if not s_strip:
            continue
        for r in route_re.findall(s_strip):
            if r not in routes:
                routes.append(r)
        for a in action_re.findall(s_strip):
            if a not in actions:
                actions.append(a)
        for u in uuid_re.findall(s_strip):
            if u not in uuids:
                uuids.append(u)
        if len(s_strip) >= 2 and _looks_like_natural_string(s_strip):
            if s_strip not in clean_strings:
                clean_strings.append(s_strip)

    for m in uuid_re.finditer(raw_latin1):
        u = m.group(0)
        if u not in uuids:
            uuids.append(u)

    if session_token is None and uuids:
        session_token = uuids[0]

    return {
        "summary": {
            "session_token": session_token,
            "resolved_username": resolved_username,
            "next_screen_routes": routes,
            "next_action_endpoints": actions,
            "extracted_uuids": uuids,
            "readable_strings": clean_strings,
        },
        "protobuf_tree": tree,
    }
