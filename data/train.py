import os, json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
import joblib

# --- Load ---
df = pd.read_csv("phishing.csv")

# --- Clean up columns (drop empty/unnamed/index-like) ---
drop_like = set()
for c in df.columns:
    cl = c.strip().lower()
    if cl.startswith("unnamed") or cl in {"id","index"}:
        drop_like.add(c)
if drop_like:
    df = df.drop(columns=list(drop_like), errors="ignore")

# --- Find label column automatically ---
label_col = None
for cand in ["Result","Label","Class","CLASS","class","status","target","Target"]:
    if cand in df.columns:
        label_col = cand
        break

# Fallback: if still None, assume the last column is the label
if label_col is None:
    label_col = df.columns[-1]

print(f"Using label column: {label_col}")

# --- y (map {-1,1} -> {0,1} if needed) ---
y_raw = df[label_col]
if set(np.unique(y_raw)).issubset({-1, 0, 1}):
    y = y_raw.replace({-1:0}).astype(int)
else:
    y = y_raw.astype(int)

# --- X (numeric features only) ---
X = df.drop(columns=[label_col])
for col in X.columns:
    X[col] = pd.to_numeric(X[col], errors="coerce")
X = X.fillna(0)

# --- Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# --- Model (solid baseline) ---
clf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced"
)
clf.fit(X_train, y_train)

# --- Evaluate ---
y_pred = clf.predict(X_test)
print("\nClassification report (1 = phishing, 0 = legit):")
print(classification_report(y_test, y_pred, digits=4))
print("Confusion matrix [[TN FP]\n [FN TP]]:")
print(confusion_matrix(y_test, y_pred))

# --- Save model + feature order ---
os.makedirs("models", exist_ok=True)
joblib.dump(clf, "phish_rf.joblib")
with open("feature_columns.json", "w") as f:
    json.dump(list(X.columns), f)
print("\n✅ Saved: models/phish_rf.joblib + models/feature_columns.json")
