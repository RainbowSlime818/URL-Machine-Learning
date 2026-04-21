import customtkinter as ctk
from tkinter import messagebox
import db_manager
import joblib
import pandas as pd
import re

# --- GUI THEME SETTINGS ---
# This automatically matches your Mac's dark/light mode!
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# --- 1. LOAD THE AI MODEL ---
try:
    model = joblib.load('phishing_model.pkl')
    print("AI Model loaded successfully.")
except FileNotFoundError:
    print("Error: 'phishing_model.pkl' not found. Please run ml_model.py first.")
    model = None


# --- 2. FEATURE EXTRACTION SIMULATOR ---
def extract_features(url):
    """Simulates extracting the 30 features our model needs."""
    having_ip = -1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 1
    url_length = -1 if len(url) > 75 else (0 if len(url) > 54 else 1)
    having_at_symbol = -1 if '@' in url else 1
    prefix_suffix = -1 if '-' in url else 1
    double_slash = -1 if url.count('//') > 1 else 1

    features = {
        'having_IPhaving_IP_Address': having_ip, 'URLURL_Length': url_length, 'Shortining_Service': 1,
        'having_At_Symbol': having_at_symbol, 'double_slash_redirecting': double_slash, 'Prefix_Suffix': prefix_suffix,
        'having_Sub_Domain': 0, 'SSLfinal_State': 0, 'Domain_registeration_length': 0, 'Favicon': 1, 'port': 1,
        'HTTPS_token': 1, 'Request_URL': 0, 'URL_of_Anchor': 0, 'Links_in_tags': 0, 'SFH': 1, 'Submitting_to_email': 1,
        'Abnormal_URL': 1, 'Redirect': 0, 'on_mouseover': 1, 'RightClick': 1, 'popUpWidnow': 1, 'Iframe': 1,
        'age_of_domain': 0, 'DNSRecord': 1, 'web_traffic': 0, 'Page_Rank': 0, 'Google_Index': 1,
        'Links_pointing_to_page': 0, 'Statistical_report': 1
    }
    return pd.DataFrame([features])


# --- 3. THE MAIN LOGIC ---
def analyze_url():
    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return

    # Reset UI State
    result_label.configure(text="Analyzing...", text_color="gray")
    root.update()

    # Step A: Check Database
    db_status = db_manager.check_url_in_db(url)
    if db_status == "Phishing":
        result_label.configure(text="🛑 BLOCKED: Found in Phishing Database!", text_color="#ff474c")
        return
    elif db_status == "Safe":
        result_label.configure(text="✅ SAFE: Found in Safe Database.", text_color="#2ecc71")
        return

    # Step B: AI Analysis
    if model is None:
        messagebox.showerror("Error", "AI Model is offline.")
        return

    features_df = extract_features(url)
    prediction = model.predict(features_df)[0]

    # Step C: Output & Log
    if prediction == -1:
        result_label.configure(text="⚠️ WARNING: AI Detected Phishing Link!", text_color="#ff474c")
        db_manager.log_url(url, "Phishing")
    else:
        result_label.configure(text="✅ SAFE: AI detected no immediate threats.", text_color="#2ecc71")
        db_manager.log_url(url, "Safe")


# --- 4. MODERN GUI SETUP ---
root = ctk.CTk()
root.title("Phishing Link Detector - BSc Cyber Security")
root.geometry("600x350")

# Create a main frame to hold everything neatly
frame = ctk.CTkFrame(master=root)
frame.pack(pady=20, padx=20, fill="both", expand=True)

# Title
title_label = ctk.CTkLabel(master=frame, text="Phishing Link Analyzer", font=("Roboto", 24, "bold"))
title_label.pack(pady=(20, 5))

subtitle_label = ctk.CTkLabel(master=frame, text="Powered by Machine Learning", font=("Roboto", 12), text_color="gray")
subtitle_label.pack(pady=(0, 20))

# Input Field
url_entry = ctk.CTkEntry(master=frame, placeholder_text="Paste suspicious URL here...", width=400, height=40,
                         font=("Roboto", 14))
url_entry.pack(pady=10)

# Analyze Button
analyze_button = ctk.CTkButton(master=frame, text="Analyze Link", command=analyze_url, height=40,
                               font=("Roboto", 14, "bold"))
analyze_button.pack(pady=15)

# Result Readout
result_label = ctk.CTkLabel(master=frame, text="Ready to scan.", font=("Roboto", 16, "bold"))
result_label.pack(pady=(10, 20))

root.mainloop()