import streamlit as st
import numpy as np
import pickle
import tensorflow as tf

st.set_page_config(page_title="Intelligent Intrusion Detection System", page_icon="🛡️", layout="wide")

st.title("🛡️ Deep Learning for Intelligent Intrusion Detection System")
st.write("Real-time network traffic analysis to detect cyber attacks and malicious activities.")

@st.cache_resource
def load_resources():
    model = tf.keras.models.load_model("ids_model.h5")
    with open("scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    return model, scaler

try:
    model, scaler = load_resources()
    st.success("Deep Learning Model Loaded Successfully!")
except Exception as e:
    st.error(f"Error loading model files: {e}")

st.sidebar.header("Network Traffic Parameters")

duration = st.sidebar.number_input("Duration (seconds)", min_value=0, value=0)
src_bytes = st.sidebar.number_input("Source Bytes (src_bytes)", min_value=0, value=181)
dst_bytes = st.sidebar.number_input("Destination Bytes (dst_bytes)", min_value=0, value=5450)
wrong_fragment = st.sidebar.number_input("Wrong Fragments", min_value=0, value=0)
urgent = st.sidebar.number_input("Urgent Packets", min_value=0, value=0)
hot = st.sidebar.number_input("Hot Indicators", min_value=0, value=0)
num_failed_logins = st.sidebar.number_input("Failed Logins", min_value=0, value=0)
num_compromised = st.sidebar.number_input("Compromised Conditions", min_value=0, value=0)

count = st.sidebar.number_input("Connections to same host (count)", min_value=0, value=8)
srv_count = st.sidebar.number_input("Connections to same service (srv_count)", min_value=0, value=8)

serror_rate = st.sidebar.slider("SYN Error Rate (serror_rate)", 0.0, 1.0, 0.0)
rerror_rate = st.sidebar.slider("REJ Error Rate (rerror_rate)", 0.0, 1.0, 0.0)
same_srv_rate = st.sidebar.slider("Same Service Rate", 0.0, 1.0, 1.0)
diff_srv_rate = st.sidebar.slider("Different Service Rate", 0.0, 1.0, 0.0)

dst_host_count = st.sidebar.number_input("Destination Host Count", min_value=0, value=9)
dst_host_srv_count = st.sidebar.number_input("Destination Host Srv Count", min_value=0, value=9)

if st.button("🔍 Analyze Network Traffic"):
    input_data = np.array([[
        duration, src_bytes, dst_bytes, wrong_fragment, urgent,
        hot, num_failed_logins, num_compromised, count, srv_count,
        serror_rate, rerror_rate, same_srv_rate, diff_srv_rate,
        dst_host_count, dst_host_srv_count
    ]])
    
    scaled_data = scaler.transform(input_data)
    prediction = model.predict(scaled_data)[0][0]
    
    st.subheader("Analysis Result")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="Threat Probability Score", value=f"{prediction * 100:.2f}%")
    
    with col2:
        if prediction > 0.5:
            st.error("🚨 ALERT: Malicious Cyber Activity / Intrusion Detected!")
        else:
            st.success("✅ NORMAL: Network Traffic appears Safe & Normal.")
