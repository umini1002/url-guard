
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract


BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "learning_dataset.xlsx"
OUTPUT_FILE = BASE_DIR / "learning_features.xlsx"

KEYWORDS = (
    "login", "signin", "verify", "secure",
    "account", "update", "banking", "password",
    "payment", "support", "authentication"
)

CAUTION_TLDS = {"shop", "cfd", "sbs", "xyz", "top"}

SPECIAL_CHARS = "@_%?&=+#"

EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=()
)

# XGBoost 학습 및 예측에 공통으로 사용할 피처
FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "special_char_count",
    "dot_count",
    "hyphen_count",
    "hostname_digit_count",
    "subdomain_count",
    "keyword_count",
    "has_ip",
    "has_https",
    "uses_http",
    "has_userinfo_at",
    "has_punycode",
    "has_suspicious_keyword",
    "has_caution_tld",
    "has_hostname_hyphen",
    "has_hostname_4plus_digits",
    "has_2plus_subdomains",
    "has_url_length_75plus",
    "has_encoded_chars",
    "query_parameter_count",
]


def extract_features(raw_url):
    """URL 문자열에서 정적 특징을 추출한다."""

    if pd.isna(raw_url) or not str(raw_url).strip():
        raise ValueError("URL이 비어 있습니다.")

    url = str(raw_url).strip()

    # 스킴이 없는 URL도 분석 가능하도록 처리
    has_scheme = bool(
        re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url)
    )

    parsed = urlsplit(
        url if has_scheme else "//" + url
    )

    try:
        hostname = (parsed.hostname or "").lower().rstrip(".")
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"잘못된 URL 형식: {exc}") from exc

    if not hostname:
        raise ValueError("호스트를 찾을 수 없습니다.")

    # IP 주소 여부
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    # 도메인 및 서브도메인 분석
    if has_ip:
        domain_suffix = ""
        subdomain_count = 0
    else:
        parts = EXTRACTOR(hostname)
        domain_suffix = parts.suffix
        subdomain_count = len(
            [x for x in parts.subdomain.split(".") if x]
        )

    # 의심 키워드
    matched_keywords = [
        word for word in KEYWORDS
        if re.search(
            r"(?<![a-z])" + re.escape(word) + r"(?![a-z])",
            url.lower()
        )
    ]

    # 숫자 개수
    hostname_digit_count = sum(
        char.isdigit() and char.isascii()
        for char in hostname
    )

    # 사용자 정보 영역의 @
    has_userinfo_at = int("@" in parsed.netloc)

    # 인코딩 문자
    encoded_count = len(
        re.findall(r"%[0-9a-fA-F]{2}", url)
    )

    # 쿼리 파라미터 개수
    query_parameter_count = (
        len([x for x in parsed.query.split("&") if x])
        if parsed.query else 0
    )

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "special_char_count": sum(
            url.count(char) for char in SPECIAL_CHARS
        ),
        "dot_count": hostname.count("."),
        "hyphen_count": url.count("-"),
        "hostname_digit_count": hostname_digit_count,
        "subdomain_count": subdomain_count,
        "keyword_count": len(matched_keywords),

        "has_ip": has_ip,
        "has_https": int(parsed.scheme.lower() == "https"),
        "uses_http": int(parsed.scheme.lower() == "http"),
        "has_userinfo_at": has_userinfo_at,

        "has_punycode": int(
            any(
                label.startswith("xn--")
                for label in hostname.split(".")
            )
        ),

        "has_suspicious_keyword": int(
            bool(matched_keywords)
        ),

        "has_caution_tld": int(
            domain_suffix.lower() in CAUTION_TLDS
        ),

        "has_hostname_hyphen": int(
            "-" in hostname
        ),

        "has_hostname_4plus_digits": int(
            hostname_digit_count >= 4
        ),

        "has_2plus_subdomains": int(
            subdomain_count >= 2
        ),

        "has_url_length_75plus": int(
            len(url) >= 75
        ),

        "has_encoded_chars": int(
            encoded_count > 0
        ),

        "query_parameter_count": query_parameter_count,

        # 설명용 정보
        "hostname": hostname,
        "matched_keywords": ", ".join(matched_keywords),
    }

    # 기존 규칙 기반 점수 유지
    rule_weights = {
        "has_ip": 4,
        "has_userinfo_at": 3,
        "has_punycode": 2,
        "has_suspicious_keyword": 2,
        "has_caution_tld": 2,
        "has_hostname_hyphen": 2,
        "has_hostname_4plus_digits": 2,
        "has_2plus_subdomains": 1,
        "has_url_length_75plus": 1,
        "uses_http": 1,
    }

    features["risk_score"] = sum(
        features[key] * weight
        for key, weight in rule_weights.items()
    )

    features["rule_prediction"] = int(
        features["risk_score"] >= 2
    )

    features["rule_result"] = (
        "피싱" if features["rule_prediction"] else "정상"
    )

    return features


def main():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(INPUT_FILE)

    data = pd.read_excel(INPUT_FILE)

    columns = {
        str(col).strip().lower(): col
        for col in data.columns
    }

    if "url" not in columns:
        raise ValueError("엑셀에 URL 열이 필요합니다.")

    results = []

    for index, url in enumerate(data[columns["url"]], start=2):

        try:
            results.append(extract_features(url))

        except (ValueError, TypeError) as exc:
            results.append({
                "parse_error": str(exc)
            })

            print(f"{index}행 분석 실패: {exc}")

    features_df = pd.DataFrame(results)

    output = pd.concat(
        [
            data.reset_index(drop=True),
            features_df.reset_index(drop=True)
        ],
        axis=1
    )

    output.to_excel(OUTPUT_FILE, index=False)

    print(f"특징 추출 완료: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
