from pathlib import Path

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)

from xgboost import XGBClassifier

from feature_extractor import (
    extract_features,
    FEATURE_COLUMNS,
)


BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "learning_dataset.xlsx"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "xgboost_model.pkl"


def load_dataset():

    if not DATASET_PATH.exists():
        raise FileNotFoundError(DATASET_PATH)

    df = pd.read_excel(DATASET_PATH)

    # 열 이름 통일
    df.columns = [
        str(col).strip().lower()
        for col in df.columns
    ]

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(
            "데이터셋에는 URL과 Label 열이 필요합니다."
        )

    # 라벨 검증
    df = df.dropna(subset=["url", "label"]).copy()

    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df.dropna(subset=["label"])

    if not df["label"].isin([0, 1]).all():
        raise ValueError(
            "Label은 0(정상), 1(피싱)만 허용합니다."
        )

    df["label"] = df["label"].astype(int)

    if df["label"].nunique() != 2:
        raise ValueError(
            "정상 URL과 피싱 URL이 모두 필요합니다."
        )

    return df


def prepare_features(df):

    feature_rows = []
    valid_labels = []

    for index, row in df.iterrows():

        try:
            features = extract_features(row["url"])

            feature_rows.append({
                col: features[col]
                for col in FEATURE_COLUMNS
            })

            valid_labels.append(row["label"])

        except (ValueError, TypeError) as exc:
            print(
                f"행 {index + 2} 분석 실패: {exc}"
            )

    X = pd.DataFrame(
        feature_rows,
        columns=FEATURE_COLUMNS
    )

    y = pd.Series(valid_labels, dtype=int)

    if len(X) == 0 or y.nunique() != 2:
        raise ValueError(
            "유효한 학습 데이터가 부족합니다."
        )

    return X, y


def train_and_save_model():

    print("=== 데이터 불러오기 ===")

    df = load_dataset()

    print(f"전체 데이터: {len(df)}개")
    print(df["label"].value_counts())

    print("\n=== 특징 추출 ===")

    X, y = prepare_features(df)

    print(f"유효 데이터: {len(X)}개")
    print(f"사용 피처: {len(FEATURE_COLUMNS)}개")

    # 학습 데이터와 검증 데이터 분리
    X_train, X_valid, y_train, y_valid = (
        train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )
    )

    # 클래스 불균형 대응
    negative_count = (y_train == 0).sum()
    positive_count = (y_train == 1).sum()

    scale_pos_weight = (
        negative_count / positive_count
    )

    print("\n=== XGBoost 학습 ===")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    # 검증 데이터 평가
    predictions = model.predict(X_valid)

    print("\n=== 검증 결과 ===")

    print(
        "Accuracy:",
        round(accuracy_score(y_valid, predictions), 4)
    )

    print(
        "Precision:",
        round(
            precision_score(
                y_valid,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                y_valid,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1-score:",
        round(
            f1_score(
                y_valid,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        classification_report(
            y_valid,
            predictions,
            zero_division=0
        )
    )

    # 모델 저장
    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    save_data = {
        "model": model,
        "feature_names": FEATURE_COLUMNS,
        "threshold": 0.5,
        "classes": [0, 1],
    }

    joblib.dump(save_data, MODEL_PATH)

    print("\n=== 모델 저장 완료 ===")
    print(MODEL_PATH)


if __name__ == "__main__":
    train_and_save_model()
