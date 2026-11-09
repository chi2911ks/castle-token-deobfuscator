#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import time
import uuid
from curl_cffi import requests
from castle_generator import CastleTokenGenerator, ClientProfile
from jf_decoder import parse_jf_response

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def generate_uuid7(timestamp_ms: int | None = None) -> str:
    """Tạo UUIDv7 chuẩn (48-bit timestamp_ms + version 7 + random bits) cho prelude_dispatch_id."""
    ts = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    rand_bytes = os.urandom(10)
    rand_a = int.from_bytes(rand_bytes[:2], "big") & 0x0FFF
    rand_b = int.from_bytes(rand_bytes[2:], "big") & 0x3FFFFFFFFFFFFFFF

    uuid_int = (ts & 0xFFFFFFFFFFFF) << 80
    uuid_int |= (0x7 << 76) | (rand_a << 64)
    uuid_int |= (0x2 << 62) | rand_b
    return str(uuid.UUID(int=uuid_int))


def main() -> None:
    # 1. Khởi tạo thông tin định danh đồng bộ giữa Header, Cookie (__cuid) và Castle Token
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
    )
    cuid = str(uuid.uuid4())  # Hoặc giữ cố định theo session: "eb8011a2-5cfb-49c6-b123-b47b47359790"
    now_ms = int(time.time() * 1000)

    # 2. Sinh $castle_token V3 (WcmFKZlD) bằng CastleTokenGenerator của project
    profile = ClientProfile(
        user_agent=user_agent,
        browser_version="156.0.0.0",
        device_guid=cuid,
        timezone="Asia/Bangkok",  # Tương ứng Etc/GMT-7
        tz_offset_raw=-420,
        timestamp_ms=now_ms,
    )
    generator = CastleTokenGenerator()
    castle_token = generator.generate_token(version="v3", profile=profile)["token"]

    # 3. Chuẩn bị request
    url = "https://jf.x.com/onboarding/web/actions/begin_signup_phone"

    headers = {
        "accept": "*/*",
        "accept-language": "en",
        "authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://x.com",
        "priority": "u=1, i",
        "referer": "https://x.com/",
        "sec-ch-ua": '"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "timezone": "Etc/GMT-7",
        "user-agent": user_agent,
        "x-client-transaction-id": "/pvj7S38KRM9Gl9l7BYZo/PChJVUrg/0IPxEIecDxEFLNDyIE4kt7Eug4lZFvDtNqgTkXPhdWJaNpdDHX9/COkNob047/Q",
        "x-guest-token": "2119702450022367668",
        "x-jf-client-theme": "dark",
        "x-jf-v": "JP-5",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
    }

    cookies = {
        "guest_id_marketing": "v1%3A179421142084442408",
        "guest_id_ads": "v1%3A179421142084442408",
        "gt": "2119702450022367668",
        "personalization_id": '"v1_cUbStE11MXkXRTaWxJCuJg=="',
        "guest_id": "v1%3A179421142084442408",
        "__cf_bm": "JEuL4VATyUe2LC9JNcLyqovfhpEXhUiyriQ_HWmF8KU-1794211420.7584941-1.0.1.1-jmf0BjOphs..GRKW.wxqQigI5ZlLI4paOSGmy9hz9UP5khWy8O3AaKNTprmkcXYa_aVKzGSi2BmiW.2qhsqIE4DQJBymaEKyxTFejsyci210AMZ7HEFzmN5VlZIdj9H9",
        "__cuid": cuid,
    }

    data = {
        "discoverable_by_phone": "1",
        "prelude_dispatch_id": generate_uuid7(now_ms),
        "phone": "+84332350491",
        "$castle_token": castle_token,
    }

    print(f"[*] __cuid / device_guid : {cuid}")
    print(f"[*] prelude_dispatch_id  : {data['prelude_dispatch_id']}")
    print(f"[*] $castle_token (len)  : {len(castle_token)} ({castle_token[:40]}...)")

    response = requests.post(
        url,
        headers=headers,
        cookies=cookies,
        data=data,
        impersonate="chrome",
    )

    print(f"[*] Status Code          : {response.status_code}")
    print(f"[*] Content-Type         : {response.headers.get('content-type')}")
    print(f"[*] Payload Size         : {len(response.content)} bytes")

    # Giải mã Protobuf / JP-5 binary response
    decoded = parse_jf_response(response.content)
    with open("response_signup_phone.json", "w", encoding="utf-8") as f:
        json.dump(decoded, f, indent=2, ensure_ascii=False)

    print("\n================ TÓM TẮT RESPONSE ĐÃ GIẢI MÃ ================")
    print(json.dumps(decoded["summary"], indent=2, ensure_ascii=False))
    print("\n[+] Toàn bộ cấu trúc Protobuf chi tiết đã được lưu vào: response_signup_phone.json")


if __name__ == "__main__":
    main()
