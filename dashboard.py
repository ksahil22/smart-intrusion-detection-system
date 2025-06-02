import streamlit as st
import pandas as pd
import numpy as np
from streamlit_autorefresh import st_autorefresh
import time
import matplotlib.pyplot as plt
import seaborn as sns
from collections import deque

# Load predictions (you must save and load these beforehand)
@st.cache_data
def load_prediction_stream():
    # Replace with your actual saved predictions
    # For demonstration, we'll simulate with dummy values
    # In real use: load from .csv or .pkl
    df = pd.read_csv("models/cleaned_data/streaming.csv")
    df = df.sample(frac=1)
    return df

def highlight_attack(attack_type):
    if attack_type == "Normal":
        return 'background-color: #d0f0c0'  # Light green
    elif attack_type in ['DoS', 'R2L', 'U2R']:
        return 'background-color: #ff9999'  # Light red
    elif attack_type == "Probe":
        return 'background-color: #ffe0b3'  # Light orange
    else:
        return ''

# Streamlit setup
st.set_page_config(page_title="IoT IDS Dashboard", layout="wide")
REFRESH_INTERVAL = 3

if 'refresh_interval' not in st.session_state:
    st.session_state.refresh_interval = REFRESH_INTERVAL

# Refresh every 3 seconds
st_autorefresh(interval=st.session_state.refresh_interval * 1000, key="stream_autorefresh")

st.title("Smart IDS Dashboard for IoT Devices")

# Sidebar settings
st.sidebar.header("Settings")
# Sidebar: how many samples to process per refresh
num_to_show = st.sidebar.number_input("Samples per refresh", min_value=1, max_value=1000, value=25)
st.session_state.refresh_interval = st.sidebar.slider("Refresh Interval (sec)", 1, 15, REFRESH_INTERVAL)

# Simulated cache to store the streaming index
if "stream_index" not in st.session_state:
    st.session_state.stream_index = 0

if "stream_size" not in st.session_state:
    st.session_state.stream_size = 0

# State storage for real-time charts
if 'log' not in st.session_state:
    st.session_state.log = deque(maxlen=num_to_show)
    st.session_state.stats = {'Normal': 0, 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0}

if 'data' not in st.session_state:
    st.session_state.data = load_prediction_stream()
    st.session_state.label_names = sorted(st.session_state.data["Prediction"].unique())  # Class labels

# Extract next batch
st.session_state.stream_size = min(st.session_state.stream_size + 1, num_to_show)
st.session_state.stream_index += 1
st.session_state.end_idx = st.session_state.stream_index
st.session_state.start_idx = max(0, st.session_state.end_idx - st.session_state.stream_size)

# Simulate and log a new entry
timestamp = time.strftime("%H:%M:%S")
batch = st.session_state.data.iloc[st.session_state.start_idx:st.session_state.end_idx]
st.session_state.log.appendleft({
    'Time': timestamp,
    'Protocol': st.session_state.data['Protocol'].iloc[st.session_state.end_idx],
    'Service': st.session_state.data['Service'].iloc[st.session_state.end_idx],
    'Prediction': st.session_state.data['Prediction'].iloc[st.session_state.end_idx]
    # 'Status': "✅ Normal" if st.session_state.data['Prediction'].iloc[st.session_state.end_idx] == "Normal" else "🚨 Intrusion"
})
st.session_state.stats[st.session_state.data['Prediction'].iloc[st.session_state.end_idx]] += 1

# Summary stats
col1, col2 = st.columns(2)
col1.metric("Total Processed", sum(st.session_state.stats.values()))
col2.metric("Total Attacks Detected", sum(v for k,v in st.session_state.stats.items() if k != 'Normal'))

# Detection Feed
st.subheader("Real-Time Detection Feed")
feed_df = pd.DataFrame(list(st.session_state.log))

# Apply to just the Prediction column
styled_df = feed_df.style.applymap(highlight_attack, subset=["Prediction"])
st.dataframe(styled_df, use_container_width=True)

# Charts
st.subheader("Traffic Summary")
col4, col5 = st.columns(2)

with col4:
    fig1, ax1 = plt.subplots()
    sns.barplot(x=list(st.session_state.stats.keys()), y=list(st.session_state.stats.values()), ax=ax1)
    ax1.set_title("Traffic Type Distribution")
    st.pyplot(fig1)

with col5:
    fig2, ax2 = plt.subplots()
    ax2.pie(list(st.session_state.stats.values()), labels=st.session_state.stats.keys(), autopct='%1.1f%%', startangle=90)
    ax2.axis('equal')
    st.pyplot(fig2)

# Footer
st.caption("Prototype IDS Dashboard - IoT Security")
