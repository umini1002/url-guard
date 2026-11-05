
from pathlib import Path

import joblib
import pandas as pd

from feature_extractor import (
    extract_features,
    FEATURE_COLUMNS,
)


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR / "model" / "xgboost_model.pkl"
)

_MODEL = None
_FEATURE_NAMES = None
_THRESHOLD = None


def _load_model():

    global _MODEL
    global _FEATURE_NAMES
    global _THRESHOLD

    if _MODEL is not None:
        return

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "모델 파일이 없습니다. "
            "먼저 train_model.py를 실행하세요."
        )

    saved_data = joblib.load(MODEL_PATH)

    if not isinstance(saved_data, dict):
        raise ValueError(
            "올바르지 않은 모델 파일입니다."
        )

    _MODEL = saved_data["model"]

    _FEATURE_NAMES = saved_data["feature_names"]

    _THRESHOLD = saved_data.get(
        "threshold",
        0.5
    )

    if _FEATURE_NAMES != FEATURE_COLUMNS:
        raise ValueError(
            "학습 모델과 현재 Feature 구조가 다릅니다. "
            "train_model.py를 다시 실행하세요."
        )


def predict(features: dict) -> dict:
    """
    추출된 Feature를 이용한 피싱 URL 예측
    """

    _load_model()

    missing_features = [
        col for col in _FEATURE_NAMES
        if col not in features
    ]

    if missing_features:
        raise ValueError(
            f"필수 Feature 누락: {missing_features}"
        )

    # 학습 시 사용한 피처 순서와 동일하게 구성
    input_df = pd.DataFrame(
        [[features[col] for col in _FEATURE_NAMES]],
        columns=_FEATURE_NAMES
    )

    # 피싱 확률 계산
    probabilities = _MODEL.predict_proba(input_df)[0]

    classes = list(_MODEL.classes_)

    phishing_index = classes.index(1)

    phishing_prob = float(
        probabilities[phishing_index]
    )

    # 위험도 분류
    if phishing_prob >= 0.70:
        prediction_status = "phishing"
        risk_level = "위험"

    elif phishing_prob >= 0.35:
        prediction_status = "suspicious"
        risk_level = "주의"

    else:
        prediction_status = "safe"
        risk_level = "낮음"

    return {
        "prediction": prediction_status,
        "probability": round(phishing_prob, 4),
        "risk_level": risk_level,
    }


def predict_url(url: str) -> dict:
    """
    URL을 입력받아 특징 추출부터 예측까지 수행
    """

    features = extract_features(url)

    result = predict(features)

    # 규칙 기반 분석 결과도 별도 제공
    result["rule_score"] = features["risk_score"]

    result["matched_keywords"] = (
        features["matched_keywords"]
    )

    result["hostname"] = features["hostname"]

    result["matched_rules"] = [
        key for key in [
            "has_ip",
            "has_userinfo_at",
            "has_punycode",
            "has_suspicious_keyword",
            "has_caution_tld",
            "has_hostname_hyphen",
            "has_hostname_4plus_digits",
            "has_2plus_subdomains",
            "has_url_length_75plus",
            "uses_http",
        ]
        if features[key]
    ]

    return result


if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "http://example-login.xyz",
        "https://example.com/account",
    ]

    for url in test_urls:

        try:
            result = predict_url(url)

            print("\nURL:", url)
            print("예측 결과:", result)

        except (ValueError, FileNotFoundError) as exc:
            print("분석 실패:", exc)
