import os
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Load CSV
csv_path = '../phishing_site_urls.csv'  # Update path if necessary
data = pd.read_csv(csv_path)
urls = data['URL'].astype(str).values
labels = (data['Label'] == 'bad').astype(int).values  # phishing=1, else=0

# Feature extraction function
def extract_features(url):
    parsed = urlparse(url)
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at'] = url.count('@')
    features['num_slash'] = url.count('/')
    features['has_https'] = int(parsed.scheme == 'https')
    features['has_ip'] = int(parsed.netloc.replace('.', '').isdigit())
    features['has_login'] = int('login' in url.lower())
    features['has_secure'] = int('secure' in url.lower())
    return list(features.values())

# Build feature matrix
feature_list = [extract_features(u) for u in urls]
X = np.array(feature_list)
y = np.array(labels)

# Split into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Hyperparameter tuning with GridSearchCV
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5]
}

clf = RandomForestClassifier(random_state=42)
grid_search = GridSearchCV(clf, param_grid, cv=5, scoring='accuracy', n_jobs=-1)
grid_search.fit(X_train, y_train)

best_clf = grid_search.best_estimator_

# Predictions
y_pred = best_clf.predict(X_test)

# Evaluation
print("Best Parameters:", grid_search.best
