Phishing URL Detector:
This project is a deep learning and machine learning-based web application that detects whether a given URL is phishing or legitimate. The detection is powered by a trained Random Forest classifier that learns from URL features extracted from large datasets.

Features:
Trains a machine learning model (Random Forest) on labeled URL data.
Extracts meaningful URL features like length, domain info, suspicious keywords.
Built with Python, using Pandas for data processing, scikit-learn for ML modeling.
User-friendly Flask web interface styled with Bootstrap.
Real-time classification of URLs into PHISHING or LEGITIMATE categories.
Can be deployed easily on cloud platforms like Heroku.

Technologies Used:
Python 3.x
Flask (Web framework)
scikit-learn (Machine learning)
Pandas (Data manipulation)
joblib (Model saving/loading)
Bootstrap 5 (UI)

Getting Started
Prerequisites
Python 3.7+
Install dependencies via:
pip install -r requirements.txt
Running the Project Locally

1. Train the machine learning model (optional, if you want to retrain):
python train_model.py

2. Run the Flask web app:
python app.py

3. Visit http://127.0.0.1:5000 in your web browser.

4. Enter URLs to test phishing detection.

Author
Khalid Naufal
