# Phishing Detector

## Overview
Phishing Detector is a machine learning-based web application designed to identify phishing websites and protect users from online fraud. It analyzes website URLs and other indicators to classify whether a website is **legitimate** or **phishing**.

The project helps users stay safe by detecting suspicious links before visiting harmful websites.

---

## Features
- Detects phishing websites using Machine Learning
- URL-based feature extraction
- User-friendly web interface
- Fast and accurate predictions
- Helps improve cybersecurity awareness

---

## Technologies Used
- **Python**
- **Flask / Streamlit** (depending on your project)
- **Scikit-learn**
- **Pandas**
- **NumPy**
- **HTML/CSS** (for frontend)

---

## Machine Learning Models Used
- Logistic Regression
- Random Forest
- Decision Tree
- Support Vector Machine (optional)

Best model selected based on accuracy.

---

## Dataset
The model is trained on phishing website datasets containing:
- URL length
- Presence of special characters
- HTTPS usage
- Domain age
- Number of subdomains
- Suspicious keywords
- Redirect behavior

---

## Project Structure
```bash
Phishing-Detector/
│── app.py
│── model.pkl
│── phishing_dataset.csv
│── templates/
│   └── index.html
│── static/
│   └── style.css
│── README.md
