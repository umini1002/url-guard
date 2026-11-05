from pathlib import Path

import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

from feature_extractor import extract_features
from ml_model import predict_url


BASE_DIR = Path(__file__).resolve().parent

TEST_FILE = BASE_DIR / "test_dataset.xlsx"

OUTPUT_FILE = (
    BASE_DIR / "test_results_detailed.xlsx"
)


def evaluate_performance():

    if not TEST_FILE.exists():
        raise FileNotFoundError(TEST_FILE)

    df = pd.read_excel(TEST_FILE)

    df.columns = [
        str(col).strip().lower()
        for col in df.columns
    ]

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(
            "테스트 데이터에 URL과 Label 열이 필요합니다."
        )

    df = df.dropna(
        subset=["url", "label"]
    ).copy()

    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df.dropna(subset=["label"])

    if not df["label"].isin([0, 1]).all():
        raise ValueError(
            "Label은 0 또는 1이어야 합니다."
        )

    actual_labels = []
    predicted_labels = []
    rule_predictions = []
    results = []

    for index, row in df.iterrows():

        url = row["url"]
        actual = int(row["label"])

        try:
            # XGBoost 예측
            prediction = predict_url(url)

            predicted = int(
                prediction["prediction"] != "safe"
            )

            # 규칙 기반 예측
            features = extract_features(url)

            rule_predicted = int(
                features["rule_prediction"]
            )

            actual_labels.append(actual)
            predicted_labels.append(predicted)
            rule_predictions.append(rule_predicted)

            results.append({
                "URL": url,
                "실제 라벨": actual,
                "실제 결과": (
                    "피싱" if actual == 1 else "정상"
                ),
                "ML 예측 결과": (
                    "피싱" if predicted == 1 else "정상"
                ),
                "ML 피싱 확률": prediction["probability"],
                "ML 위험도": prediction["risk_level"],
                "규칙 기반 예측": (
                    "피싱" if rule_predicted == 1 else "정상"
                ),
                "규칙 기반 점수": features["risk_score"],
                "분석 상태": "성공",
            })

        except Exception as exc:

            print(
                f"{index + 2}행 분석 실패: {exc}"
            )

            results.append({
                "URL": url,
                "실제 라벨": actual,
                "분석 상태": f"실패: {exc}",
            })

    if not actual_labels:
        raise ValueError(
            "평가 가능한 데이터가 없습니다."
        )

    # ML 모델 성능
    print("\n=== XGBoost 성능 평가 ===")

    print(
        "Accuracy:",
        round(
            accuracy_score(
                actual_labels,
                predicted_labels
            ),
            4
        )
    )

    print(
        "Precision:",
        round(
            precision_score(
                actual_labels,
                predicted_labels,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                actual_labels,
                predicted_labels,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1-score:",
        round(
            f1_score(
                actual_labels,
                predicted_labels,
                zero_division=0
            ),
            4
        )
    )

    print("\n=== Classification Report ===")

    print(
        classification_report(
            actual_labels,
            predicted_labels,
            labels=[0, 1],
            target_names=["정상", "피싱"],
            zero_division=0
        )
    )

    print("\n=== Confusion Matrix ===")

    cm = confusion_matrix(
        actual_labels,
        predicted_labels,
        labels=[0, 1]
    )

    print(cm)

    # 규칙 기반 성능
    print("\n=== 규칙 기반 성능 ===")

    print(
        "Accuracy:",
        round(
            accuracy_score(
                actual_labels,
                rule_predictions
            ),
            4
        )
    )

    print(
        "Precision:",
        round(
            precision_score(
                actual_labels,
                rule_predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                actual_labels,
                rule_predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1-score:",
        round(
            f1_score(
                actual_labels,
                rule_predictions,
                zero_division=0
            ),
            4
        )
    )

    # 결과 엑셀 저장
    results_df = pd.DataFrame(results)

    results_df.to_excel(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"\n상세 평가 결과 저장 완료: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    evaluate_performance()
