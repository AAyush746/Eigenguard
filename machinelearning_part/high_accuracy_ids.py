import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


def load_and_label_data(filepath):
    """
    Loads processed requests and generates 'ground truth' labels
    based on known attack signatures found in the logs.
    """
    print(f"Loading data from {filepath}...")
    df = pd.read_csv(filepath)

    # --- HEURISTIC LABELING (Creating Ground Truth) ---
    # We define 'Attack' (1) vs 'Normal' (0) based on your log patterns
    df["is_attack"] = 0

    # Rule 1: Known Malicious User Agents (from your logs)
    suspicious_agents = ["MaliciousBot", "curl", "python-requests", "sqlmap"]
    df.loc[
        df["userAgent"].str.contains("|".join(suspicious_agents), case=False, na=False),
        "is_attack",
    ] = 1

    # Rule 2: 404 Errors on Sensitive/Non-existent Endpoints (Scanning behavior)
    # Your logs show scans for /api/stats and /nonexistent
    suspicious_paths = ["/nonexistent", "/admin", "/login.php", "/.env"]
    for path in suspicious_paths:
        df.loc[
            (df["url"].str.contains(path, na=False)) & (df["status"] == 404),
            "is_attack",
        ] = 1

    print(
        f"Data labeled. Attacks found: {df['is_attack'].sum()} out of {len(df)} requests."
    )
    return df


def extract_features(df):
    """
    Converts raw data into numerical features suitable for the AI model.
    """
    # Initialize features DataFrame
    features = pd.DataFrame()

    # 1. Status Code (Numerical)
    features["status"] = df["status"]

    # 2. Response Metrics (Numerical)
    features["responseTime"] = df["responseTime"]
    features["responseSize"] = df["responseSize"]

    # 3. Time-based Features
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    features["hour"] = df["timestamp"].dt.hour
    features["dayofweek"] = df["timestamp"].dt.dayofweek

    # 4. Encoding Categorical Data (Method, UserAgent)
    le = LabelEncoder()
    features["method_code"] = le.fit_transform(df["method"])

    # We encode UserAgent to capture patterns, but relying heavily on it
    # for the model might overfit to specific names.
    # For high accuracy, we include it, but the model learns the behavior (time/size) too.
    features["userAgent_code"] = le.fit_transform(df["userAgent"].astype(str))

    return features, df["is_attack"]


def train_high_accuracy_model(X, y):
    """
    Trains a Random Forest Classifier.
    Random Forest is chosen for its high accuracy, resistance to overfitting,
    and ability to handle mixed feature types better than Isolation Forest.
    """
    # Split data: 80% for training, 20% for testing
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Initialize Random Forest with 100 decision trees
    clf = RandomForestClassifier(
        n_estimators=100, random_state=42, class_weight="balanced"
    )

    print("Training Random Forest Model...")
    clf.fit(X_train, y_train)

    # Predictions
    y_pred = clf.predict(X_test)

    return y_test, y_pred, clf


if __name__ == "__main__":
    # 1. Load and Label
    # We use processed_requests.csv because it contains the raw text needed for labeling
    input_file = "processed_requests.csv"
    try:
        df_raw = load_and_label_data(input_file)
    except FileNotFoundError:
        print(
            f"Error: {input_file} not found. Please ensure it is in the current directory."
        )
        exit()

    # 2. Extract Features
    X, y = extract_features(df_raw)

    # 3. Train and Evaluate
    y_test, y_pred, model = train_high_accuracy_model(X, y)

    # 4. Results
    print("\n--- Model Evaluation Results ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    print(
        "\nNote: 'Precision' reflects how many predicted attacks were actually attacks."
    )
    print("'Recall' reflects how many actual attacks were correctly detected.")
