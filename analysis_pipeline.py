"""Team Python AI/Rule → report_generator adapter (same policy as hosted API)."""
import json
import math
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "ai"))
from feature_extractor import extract_features
from ml_model import predict
from report_generator import generate_report

RULES = [
    ("has_ip", 4, "도메인명 대신 IP 주소를 사용합니다."),
    ("has_userinfo_at", 3, "주소에 @ 기호가 있는 사용자 정보 영역이 포함되어 있습니다."),
    ("has_punycode", 2, "국제화 도메인을 나타내는 퓨니코드가 포함되어 있습니다."),
    ("has_suspicious_keyword", 2, "로그인·인증 관련 키워드가 포함되어 있습니다."),
    ("has_caution_tld", 2, "룰 목록의 주의 대상 최상위 도메인을 사용합니다."),
    ("has_hostname_hyphen", 2, "호스트 이름에 하이픈(-)이 포함되어 있습니다."),
    ("has_hostname_4plus_digits", 2, "호스트 이름에 숫자가 4개 이상 포함되어 있습니다."),
    ("has_2plus_subdomains", 1, "하위 도메인이 2단계 이상입니다."),
    ("has_url_length_75plus", 1, "주소 길이가 75자 이상입니다."),
    ("uses_http", 1, "HTTPS 대신 HTTP를 사용합니다."),
]
RULE_MAX_SCORE = sum(weight for _, weight, _ in RULES)
POLICY = {"ai_weight": .8, "rule_weight": .2, "rule_max_score": RULE_MAX_SCORE,
          "medium_threshold": 35, "high_threshold": 70, "status": "provisional"}


def analyze_url(raw):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096 or re.search(r"[\s\x00-\x1f\x7f\\]", raw.strip()):
        raise ValueError("공백 없는 올바른 웹 주소를 입력해 주세요.")
    url = raw.strip()
    has_scheme = bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url))
    parsed = urlsplit(url if has_scheme else "https://" + url)
    _ = parsed.port
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("http 또는 https 웹 주소를 입력해 주세요.")
    hostname = parsed.hostname.rstrip(".")
    if "." not in hostname and ":" not in hostname and hostname != "localhost":
        raise ValueError("올바른 도메인 주소를 입력해 주세요.")
    features = extract_features(url)
    ai = predict(features)
    matched = [(key, message) for key, _, message in RULES if features[key]]
    reasons = [f"로그인·인증 관련 키워드 발견: {features['matched_keywords']}" if key == "has_suspicious_keyword" else message for key, message in matched]
    report = generate_report(url, ai, {"rule_score": features["risk_score"], "reason": reasons}, rule_max_score=RULE_MAX_SCORE)
    level = report["risk_level"]
    report["attack_type"] = "확인된 공격 유형 없음" if level == "LOW" else "피싱 의심 — 세부 공격 유형은 확인되지 않았습니다."
    report["recommendation"] = {
        "LOW": "개인정보를 입력하기 전에 주소와 출처를 확인하세요. 낮은 점수도 안전을 보장하지 않습니다.",
        "MEDIUM": "링크 접속과 개인정보 입력을 보류하고, 공식 앱이나 확인된 주소로 직접 접속하세요.",
        "HIGH": "해당 사이트에 계정·결제 정보를 입력하지 마세요. 공식 경로로 진위를 확인하세요.",
    }[level]
    report.update(features=features, matched_rules=[key for key, _ in matched],
                  matched_keywords=[word for word in features["matched_keywords"].split(", ") if word],
                  probability=ai["probability"], ai_prediction=ai["prediction"],
                  rule_score=features["risk_score"], rule_max_score=RULE_MAX_SCORE,
                  model="XGBoost", training_data="team_provided_dataset", policy=POLICY,
                  source_commit="e9853c28b06f591fac8ce27c0d63fb05124b818b")
    from datetime import datetime, timezone
    report["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    return report
