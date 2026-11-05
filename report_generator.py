"""AI + Rule 결과를 사용자용 리포트로 변환. 외부 패키지/네트워크 불필요.

기본 정책(팀 합의 전 임시값): AI 80%, Rule 20%, Rule 점수 범위 0~100.
최종 점수는 위험 지표이며 보정된 피싱 확률이 아니다.
실행: python -X utf8 report_generator.py
"""

import json
import math
from collections.abc import Mapping
from decimal import Decimal, ROUND_HALF_UP
from numbers import Real


# 룰 담당자와 합의하여 코드와 문구를 추가할 수 있다.
REASON_LABELS = {
    "LOGIN_KEYWORD": "login 키워드 발견",
    "LOGIN KEYWORD DETECTED": "login 키워드 발견",
    "NO_HTTPS": "HTTPS 미사용",
    "HTTPS NOT USED": "HTTPS 미사용",
    "IP_ADDRESS": "도메인명 대신 IP 주소 사용",
    "IP ADDRESS DETECTED": "도메인명 대신 IP 주소 사용",
    "SUSPICIOUS_DOMAIN": "의심스러운 도메인 구조 감지",
}
ATTACK_LABELS = {
    "CREDENTIAL_PHISHING": "계정 정보 탈취형 피싱",
    "계정 정보 탈취형 피싱": "계정 정보 탈취형 피싱",
    "MALWARE_DISTRIBUTION": "악성코드 유포 의심",
    "악성코드 유포 의심": "악성코드 유포 의심",
    "PHISHING": "피싱 의심 — 세부 유형 미확인",
}
RECOMMENDATIONS = {
    "LOW": "탐지된 위험이 낮아도 안전을 보장하지 않습니다. 개인정보 입력 전 주소와 출처를 확인하세요.",
    "MEDIUM": "링크 접속과 개인정보 입력을 보류하고, 공식 앱이나 확인된 주소로 직접 접속하세요.",
    "HIGH": "사이트에 접속하거나 계정·결제 정보를 입력하지 마세요. 공식 경로로 진위를 확인하세요.",
}


def _number(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name}은 숫자여야 합니다.")
    value = float(value)
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{name}은 {minimum}~{maximum} 범위의 유한한 숫자여야 합니다.")
    return value


def _reasons(value):
    if not isinstance(value, list):
        raise ValueError("rule_result.reason은 문자열 목록이어야 합니다.")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("reason의 각 항목은 비어 있지 않은 문자열이어야 합니다.")
        item = item.strip()
        label = REASON_LABELS.get(item.upper(), item)
        if label not in result:
            result.append(label)
    return result


def generate_report(
    url,
    ai_result,
    rule_result,
    *,
    ai_weight=0.8,
    rule_max_score=100,
    medium_threshold=35,
    high_threshold=70,
):
    """최소 입력 규약:

    ai_result = {"probability": 0.85}
    rule_result = {"rule_score": 40, "reason": ["LOGIN_KEYWORD", "NO_HTTPS"]}

    선택: rule_result["attack_type"]에 근거가 있는 유형 코드를 전달.
    지원 코드: CREDENTIAL_PHISHING, MALWARE_DISTRIBUTION, PHISHING.
    키워드만 보고 공격 유형을 생성하지 않는다. 미제공/미지원은 판별 불가.
    누락/잘못된 입력은 ValueError. URL은 표시용으로 유지하며 접속하지 않는다.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url은 비어 있지 않은 문자열이어야 합니다.")
    if not isinstance(ai_result, Mapping) or not isinstance(rule_result, Mapping):
        raise ValueError("ai_result와 rule_result는 딕셔너리여야 합니다.")
    if "probability" not in ai_result:
        raise ValueError("ai_result.probability가 필요합니다.")
    if "rule_score" not in rule_result or "reason" not in rule_result:
        raise ValueError("rule_result.rule_score와 reason이 필요합니다.")

    probability = _number(ai_result["probability"], "probability", 0, 1)
    weight = _number(ai_weight, "ai_weight", 0, 1)
    if isinstance(rule_max_score, bool) or not isinstance(rule_max_score, Real):
        raise ValueError("rule_max_score는 양수여야 합니다.")
    maximum = float(rule_max_score)
    if not math.isfinite(maximum) or maximum <= 0:
        raise ValueError("rule_max_score는 유한한 양수여야 합니다.")
    rule_score = _number(rule_result["rule_score"], "rule_score", 0, maximum)
    medium = _number(medium_threshold, "medium_threshold", 0, 100)
    high = _number(high_threshold, "high_threshold", 0, 100)
    if medium >= high:
        raise ValueError("medium_threshold는 high_threshold보다 작아야 합니다.")

    # Decimal을 사용하여 34.5 → 35 등 반올림 정책을 일관되게 적용.
    p, w = Decimal(str(probability)), Decimal(str(weight))
    normalized_rule = Decimal(str(rule_score)) / Decimal(str(maximum)) * 100
    combined = p * 100 * w + normalized_rule * (1 - w)
    score = int(combined.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    # 화면에 표시할 최종 점수와 같은 값으로 등급을 판정한다.
    level = "HIGH" if score >= high else "MEDIUM" if score >= medium else "LOW"
    reasons = _reasons(rule_result["reason"])

    attack_code = rule_result.get("attack_type")
    if attack_code is not None and not isinstance(attack_code, str):
        raise ValueError("attack_type은 문자열이어야 합니다.")
    attack_type = ATTACK_LABELS.get(
        attack_code.strip() if attack_code is not None else None,
        "판별 불가 — 공격 유형 정보가 제공되지 않았습니다.",
    )
    recommendation = RECOMMENDATIONS[level]
    if attack_type == ATTACK_LABELS["MALWARE_DISTRIBUTION"]:
        recommendation = "해당 사이트의 파일을 내려받거나 실행하지 마세요. 이미 다운로드했다면 실행하지 말고 보안 검사를 진행하세요."
    elif attack_type == ATTACK_LABELS["CREDENTIAL_PHISHING"]:
        recommendation = "사이트에 계정·결제 정보를 입력하지 마세요. 이미 입력했다면 공식 경로에서 비밀번호를 변경하고 다중 인증을 설정하세요."

    return {
        "url": url.strip(),
        "risk_level": level,
        "risk_score": score,
        "reason": reasons,
        "attack_type": attack_type,
        "recommendation": recommendation,
    }


if __name__ == "__main__":
    example = generate_report(
        "http://fake-login.com",
        {"probability": 0.85},
        {"rule_score": 40, "reason": ["LOGIN_KEYWORD", "NO_HTTPS"]},
    )
    print(json.dumps(example, ensure_ascii=False, indent=2))
