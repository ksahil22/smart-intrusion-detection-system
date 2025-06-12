# 🔐 Intrunet - Intrusion Detection System for IoT Devices

This repository contains the code and resources for our project **"Intrunet Intrusion Detection System (IDS) for IoT Devices"**, developed as part of a course on Software Security and Dependability.

The system leverages machine learning and deep learning techniques to detect various types of network intrusions using the NSL-KDD dataset. It features a trained Multi-Layer Perceptron (MLP) model integrated with a real-time Streamlit-based dashboard for monitoring predictions.

---

## 📁 Contents

- `data/` — NSL-KDD dataset files
- `AI-IDS.ipynb` — Data cleaning, feature engineering, and preprocessing steps
- `models/` — saved models (Random Forest, XGBoost, LightGBM, MLP)
- `dashboard.py` — Real-time Streamlit dashboard application

---

## ⚙️ Technologies Used

- Python
- Scikit-learn
- TensorFlow / Keras
- XGBoost, LightGBM
- Pandas, NumPy, Matplotlib, Seaborn
- Streamlit (for real-time dashboard)

---

## 🧠 Features & Models

We experimented with several ML models:
- ✅ Random Forest
- ✅ XGBoost
- ✅ LightGBM
- ✅ MLP (Multi-Layer Perceptron) — **final model**

The MLP model structure:
- Input Layer: Number of features after preprocessing
- Hidden Layers: 128 → 64 → 32 neurons (ReLU activations)
- Dropout layers to prevent overfitting
- Output Layer: 5-class Softmax (Normal, DoS, Probe, R2L, U2R)

---

## 📊 Dashboard

A user-friendly real-time dashboard built using **Streamlit** displays:
- Incoming IoT traffic records
- Predicted attack categories
- Color-coded alerts for anomaly detection
- Expandable views for full feature inspection
- [![Watch the video](readme/dashboard.png)](readme/Dashboard.mp4)

---

## 🔄 How to Run

1. **Install streamlit**
2. streamlit run dashboard.py
