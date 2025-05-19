import streamlit as st
import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns
from collections import deque

# Simulated prediction stream (replace with real-time data ingestion)
def simulate_detection():
    attack_types = ['Normal', 'DoS', 'Botnet', 'Probe', 'BruteForce']
    prediction = np.random.choice(attack_types, p=[0.85, 0.05, 0.04, 0.04, 0.02])
    confidence = round(np.random.uniform(0.85, 1.0), 2)
    return prediction, confidence

# Streamlit setup
st.set_page_config(page_title="IoT IDS Dashboard", layout="wide")
st.title("Smart IDS Dashboard for IoT Devices")

# State storage for real-time charts
if 'log' not in st.session_state:
    st.session_state.log = deque(maxlen=100)
    st.session_state.stats = {'Normal': 0, 'DoS': 0, 'Botnet': 0, 'Probe': 0, 'BruteForce': 0}

# Sidebar settings
st.sidebar.header("Settings")
thresh = st.sidebar.slider("Confidence Threshold", 0.80, 1.00, 0.90, 0.01)
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
refresh_interval = st.sidebar.slider("Refresh Interval (sec)", 1, 10, 3)

# Simulate and log a new entry
if auto_refresh or st.button("Manual Refresh"):
    pred, conf = simulate_detection()
    timestamp = time.strftime("%H:%M:%S")
    alert = conf >= thresh
    st.session_state.log.appendleft({
        'Time': timestamp,
        'Prediction': pred,
        'Confidence': conf,
        'Alert': alert
    })
    st.session_state.stats[pred] += 1
    time.sleep(refresh_interval if auto_refresh else 0)

# Summary stats
col1, col2, col3 = st.columns(3)
col1.metric("Total Processed", sum(st.session_state.stats.values()))
col2.metric("Total Attacks Detected", sum(v for k,v in st.session_state.stats.items() if k != 'Normal'))
col3.metric("Threshold", f">= {thresh}")

# Detection Feed
st.subheader("Real-Time Detection Feed")
feed_df = pd.DataFrame(list(st.session_state.log))
st.dataframe(feed_df, use_container_width=True)

# Charts
st.subheader("Traffic Summary")
col4, col5 = st.columns(2)

with col4:
    fig1, ax1 = plt.subplots()
    sns.barplot(x=list(st.session_state.stats.keys()), y=list(st.session_state.stats.values()), ax=ax1)
    ax1.set_title("Traffic Type Distribution")
    st.pyplot(fig1)

with col5:
    alert_counts = [entry['Alert'] for entry in st.session_state.log].count(True)
    normal_counts = len(st.session_state.log) - alert_counts
    fig2, ax2 = plt.subplots()
    ax2.pie([normal_counts, alert_counts], labels=['Normal', 'Alerts'], autopct='%1.1f%%', startangle=90)
    ax2.axis('equal')
    st.pyplot(fig2)

# Footer
st.caption("Prototype IDS Dashboard - IoT Security")
