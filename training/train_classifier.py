"""
SentinelDLP - Offline AI Model Training Pipeline
Trains TF-IDF feature vectorizer and multi-tier sensitivity classifier, evaluates metrics,
and exports production artifacts to backend/ai/models/.
"""

import os
import sys
import joblib
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score, precision_score, recall_score

from training.sample_data import get_training_dataset
from backend.database import SessionLocal, Base, engine
from backend.ai.model_manager import model_manager


def train():
    print("=" * 60)
    print(" SentinelDLP - Training AI Content Classification Engine ")
    print("=" * 60)

    # 1. Generate / load training corpus
    print("[*] Generating synthetic multi-tier enterprise dataset...")
    texts, tiers, categories = get_training_dataset(augment_factor=60)
    print(f"[+] Loaded {len(texts)} training samples across 5 sensitivity tiers.")

    # 2. Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        texts, tiers, test_size=0.2, random_state=42, stratify=tiers
    )
    print(f"[+] Train split: {len(X_train)} samples | Test split: {len(X_test)} samples")

    # 3. Fit TF-IDF Vectorizer
    print("[*] Fitting TF-IDF Vectorizer (ngram_range=(1,2), max_features=5000)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True,
        stop_words="english"
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"[+] Extracted {X_train_vec.shape[1]} unique n-gram features.")

    # 4. Fit Multi-Class Logistic Regression Classifier
    print("[*] Training calibrated Logistic Regression Classifier...")
    model = LogisticRegression(
        C=10.0,
        max_iter=1000,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train_vec, y_train)

    # 5. Evaluate Model
    print("[*] Evaluating model performance on held-out test split...")
    y_pred = model.predict(X_test_vec)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted")
    rec = recall_score(y_test, y_pred, average="weighted")
    f1 = f1_score(y_test, y_pred, average="weighted")

    print("\n" + "=" * 60)
    print(" Model Evaluation Report:")
    print("=" * 60)
    print(classification_report(y_test, y_pred))
    print(f"Overall Accuracy:  {acc * 100:.2f}%")
    print(f"Weighted Precision: {prec * 100:.2f}%")
    print(f"Weighted Recall:    {rec * 100:.2f}%")
    print(f"Weighted F1-Score:  {f1 * 100:.2f}%")
    print("=" * 60)

    # 6. Save Artifacts to backend/ai/models/
    model_dir = BASE_DIR / "backend" / "ai" / "models"
    os.makedirs(model_dir, exist_ok=True)

    model_path = model_dir / "dlp_classifier.joblib"
    vectorizer_path = model_dir / "dlp_vectorizer.joblib"

    print(f"[*] Exporting model artifacts to {model_dir}...")
    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    print(f"[+] Saved classifier to: {model_path}")
    print(f"[+] Saved vectorizer to: {vectorizer_path}")

    # 7. Register / Update Metadata in Database
    try:
        db = SessionLocal()
        model_manager.register_model_metadata(
            db=db,
            model_name="sentineldlp-classifier",
            model_version="v2.3.0",
            model_type="CLASSIFIER",
            status="PRODUCTION",
            precision_score=prec,
            recall_score=rec,
            f1_score=f1,
            feature_count=X_train_vec.shape[1],
            training_sample_count=len(texts)
        )
        db.close()
        print("[+] Model metadata registered in database registry.")
    except Exception as e:
        print(f"[-] Database registration skipped or failed: {e}")

    print("\n[SUCCESS] AI Model Training Pipeline completed successfully!")


if __name__ == "__main__":
    train()
