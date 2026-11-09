#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
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


def main() -> None:
    # Thông tin đăng nhập
    username_or_email = "chi2911ksO"
    fallback_username = "chi2911ksO"
    password = "Chi@29112004"

    # 1. Khởi tạo thông tin định danh đồng bộ giữa Header, Cookie (__cuid) và Castle Token
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
    )
    cuid = str(uuid.uuid4())  # Hoặc giữ cố định: "eb8011a2-5cfb-49c6-b123-b47b47359790"

    profile = ClientProfile(
        user_agent=user_agent,
        browser_version="156.0.0.0",
        device_guid=cuid,
        timezone="Asia/Bangkok",  # Tương ứng Etc/GMT-7
        tz_offset_raw=-420,
    )
    generator = CastleTokenGenerator()

    # 2. Khởi tạo Session dùng chung cho cả 2 bước (begin_login -> login_enter_password)
    session = requests.Session(impersonate="chrome")

    common_headers = {
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
        "x-jf-client-theme": "dark",
        "x-jf-v": "JP-5",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
    }
    session.headers.update(common_headers)

    initial_cookies = {
        "guest_id_marketing": "v1%3A179421142084442408",
        "guest_id_ads": "v1%3A179421142084442408",
        "gt": "2119702450022367668",
        "personalization_id": '"v1_cUbStE11MXkXRTaWxJCuJg=="',
        "guest_id": "v1%3A179421142084442408",
        "__cuid": cuid,
        "__cf_bm": "ZDLvmIBR9loquzDUaFTAuF9lbc1F1lxcg0ZbDnCQ5Hs-1794212631.8495522-1.0.1.1-6gJjnDbB2tqICkLU.hCeDLO89yRfRTTO798M_lcGzNuwKUioHtKn4ngAjAh3b20IV5Xo_QA_OLT9FZcpKLMeBUvX0Sg2iN0zfFi_rcLMeQXvQYAyl..zWT20z9PC5XDP",
    }
    session.cookies.update(initial_cookies)

    # =========================================================================
    # BƯỚC 1: POST /onboarding/web/actions/begin_login
    # =========================================================================
    print("=" * 72)
    print(" [BƯỚC 1] GỬI REQUEST: begin_login")
    print("=" * 72)

    ts_step1 = int(time.time() * 1000)
    castle_token_1 = generator.generate_token(
        version="v3", profile=profile, timestamp_ms=ts_step1
    )["token"]

    headers_step1 = {
        "x-client-transaction-id": "85bu4CDxJB4wF1Jo4RsUrv7PiZhZowL5LfFJLOoOyUxGOTGFHoQg4Uat71tIsTZAp87TUfVMCYBAgXp9Aw/YXl3r8TNC8A",
        
    }
    data_step1 = {
        "username_or_email": username_or_email,
        "password": password,
        "$castle_token": castle_token_1,
    }

    print(f"[*] __cuid / device_guid : {cuid}")
    print(f"[*] username_or_email    : {username_or_email}")
    print(f"[*] $castle_token (1)    : {len(castle_token_1)} chars ({castle_token_1[:40]}...)")

    resp1 = session.post(
        "https://jf.x.com/onboarding/web/actions/begin_login",
        headers=headers_step1,
        data=data_step1,
    )

    print(f"[*] Status Code (Bước 1) : {resp1.status_code}")
    decoded_1 = parse_jf_response(resp1.content)
    with open("response_step1_begin_login.json", "w", encoding="utf-8") as f:
        json.dump(decoded_1, f, indent=2, ensure_ascii=False)

    summary_1 = decoded_1["summary"]
    print(json.dumps(summary_1, indent=2, ensure_ascii=False))

    session_token = summary_1.get("session_token")
    resolved_username = summary_1.get("resolved_username") or fallback_username

    if not session_token:
        print("\n[!] Không tìm thấy session_token trong response Bước 1. Dừng luồng.")
        return

    # =========================================================================
    # BƯỚC 2: POST /onboarding/web/actions/login_enter_password
    # =========================================================================
    print("\n" + "=" * 72)
    print(" [BƯỚC 2] GỬI REQUEST: login_enter_password (cùng Session)")
    print("=" * 72)

    ts_step2 = int(time.time() * 1000)
    castle_token_2 = generator.generate_token(
        version="v3", profile=profile, timestamp_ms=ts_step2
    )["token"]

    headers_step2 = {
        "x-client-transaction-id": "MlcvIeEw5d/x1pOpINrVbz8OSFmYYsM47DCI7SvPCI2H+PBE30XhIIdsLpqJcPeBZpBykDQsr+Z8fdWnU/N2WOqSSnVEMQ",
    }
    data_step2 = {
        "username": resolved_username,
        "password": password,
        "session_token": session_token,
        "$castle_token": castle_token_2,
    }

    print(f"[*] username             : {resolved_username}")
    print(f"[*] password             : {'*' * len(password)}")
    print(f"[*] session_token        : {session_token}")
    print(f"[*] $castle_token (2)    : {len(castle_token_2)} chars ({castle_token_2[:40]}...)")

    resp2 = session.post(
        "https://jf.x.com/onboarding/web/actions/login_enter_password",
        headers=headers_step2,
        data=data_step2,
    )

    print(f"[*] Status Code (Bước 2) : {resp2.status_code}")
    print(f"[*] Response Cookies     : {dict(session.cookies)}")

    decoded_2 = parse_jf_response(resp2.content)
    with open("response_step2_enter_password.json", "w", encoding="utf-8") as f:
        json.dump(decoded_2, f, indent=2, ensure_ascii=False)

    print("\n================ TÓM TẮT RESPONSE BƯỚC 2 ================")
    print(json.dumps(decoded_2["summary"], indent=2, ensure_ascii=False))
    print("\n[+] Đã lưu chi tiết Bước 1 -> response_step1_begin_login.json")
    print("[+] Đã lưu chi tiết Bước 2 -> response_step2_enter_password.json")


if __name__ == "__main__":
    main()
