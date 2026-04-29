import customtkinter as ctk
from tkinter import messagebox
import db_manager
import joblib
import pandas as pd
import re
import urllib.parse

# --- GUI THEME SETTINGS ---
# Matches the user's OS preference (Dark/Light mode) automatically
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# --- 1. LOAD THE AI MODEL & FEATURE LIST ---
try:
    # Load the trained machine learning model
    model = joblib.load('phishing_model_v2.pkl')

    # Load the exact 98 column names the model was trained on so we can match them perfectly
    EXPECTED_FEATURES = joblib.load('model_features.pkl')
    print("AI Model (v2) and Feature Map loaded successfully.")
except FileNotFoundError:
    print("Error: Model files not found. Please run ml_model.py first.")
    model = None
    EXPECTED_FEATURES = []


# --- 2. DYNAMIC FEATURE EXTRACTOR ---
def extract_features(url: str) -> pd.DataFrame:
    """
    Takes a single URL string, breaks it into structural components (Domain, Path, File, Query),
    and counts the occurrences of specific symbols to recreate the 98 features the AI expects.
    """
    # 1. Normalize the URL: urllib.parse fails if there is no protocol (http/https).
    # If the user just pastes "google.com", we prepend "http://" to ensure it parses correctly.
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # 2. Dissect the URL into its core components
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc  # e.g., "www.paypal.com"
    path = parsed.path  # e.g., "/login/auth"
    query = parsed.query  # e.g., "user=admin&id=1"

    # Split the path further into "Directory" and "File"
    if '/' in path:
        # Splits from the right. "/a/b/c.php" becomes directory "/a/b/" and file "c.php"
        directory = path.rsplit('/', 1)[0] + '/'
        file = path.rsplit('/', 1)[1]
    else:
        directory = ''
        file = path

    # A dictionary of special characters phishers frequently use to trick victims
    chars = {
        'dot': '.', 'hyphen': '-', 'underline': '_', 'slash': '/',
        'questionmark': '?', 'equal': '=', 'at': '@', 'and': '&',
        'exclamation': '!', 'space': ' ', 'tilde': '~', 'comma': ',',
        'plus': '+', 'asterisk': '*', 'hashtag': '#', 'dollar': '$', 'percent': '%'
    }

    # Dictionary to hold our generated features before converting to a DataFrame
    features = {}

    # --- A. Full URL Features ---
    # Loop through our characters and count them in the entire URL string
    for name, char in chars.items():
        features[f'qty_{name}_url'] = url.count(char)

    features['length_url'] = len(url)
    # Check if a raw email address is buried in the URL (a common tactic in spear-phishing)
    features['email_in_url'] = 1 if re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', url) else 0
    features['qty_tld_url'] = 1  # Approximation for the Top Level Domain count

    # --- B. Domain Features ---
    for name, char in chars.items():
        features[f'qty_{name}_domain'] = domain.count(char)

    # Count vowels: Legitimate domains use words. Bot-generated domains (e.g., xzqk.com) lack vowels.
    features['qty_vowels_domain'] = sum(1 for c in domain.lower() if c in 'aeiou')
    features['domain_length'] = len(domain)
    # Check if the domain is just an IP address (e.g., 192.168.1.1) instead of a real name
    features['domain_in_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
    # Phishers often use tech-sounding words to look official
    features['server_client_domain'] = 1 if 'server' in domain.lower() or 'client' in domain.lower() else 0

    # --- C. Directory Features (-1 implies the URL has no directory) ---
    if not directory or directory == '/':
        for name in chars.keys(): features[f'qty_{name}_directory'] = -1
        features['directory_length'] = -1
    else:
        for name, char in chars.items(): features[f'qty_{name}_directory'] = directory.count(char)
        features['directory_length'] = len(directory)

    # --- D. File Features (-1 implies the URL points to a folder, not a specific file) ---
    if not file:
        for name in chars.keys(): features[f'qty_{name}_file'] = -1
        features['file_length'] = -1
    else:
        for name, char in chars.items(): features[f'qty_{name}_file'] = file.count(char)
        features['file_length'] = len(file)

    # --- E. Parameter Features (Data sent after the '?' symbol) ---
    if not query:
        for name in chars.keys(): features[f'qty_{name}_params'] = -1
        features['params_length'] = -1
        features['qty_params'] = -1
        features['tld_present_params'] = -1
    else:
        for name, char in chars.items(): features[f'qty_{name}_params'] = query.count(char)
        features['params_length'] = len(query)
        # Parameters are separated by '&', so 1 '&' means 2 parameters.
        features['qty_params'] = query.count('&') + 1
        features['tld_present_params'] = 0

        # --- F. ALIGN WITH MODEL ---
    # The AI will crash if we hand it a column it doesn't recognize or if we miss one.
    # We loop through EXPECTED_FEATURES (loaded from the .pkl map) to ensure absolute perfection.
    for col in EXPECTED_FEATURES:
        if col not in features:
            features[col] = 0  # Default missing features to 0

    # Convert the dictionary to a 2D Pandas array, strictly enforcing the column order
    return pd.DataFrame([features])[EXPECTED_FEATURES]


# --- 3. THE MAIN APPLICATION LOGIC ---
def analyze_url():
    """
    Triggered when the user clicks the 'Analyze Link' button.
    Coordinates the cache check, feature extraction, AI prediction, and database logging.
    """
    url = url_entry.get().strip()  # .strip() removes accidental leading/trailing spaces

    # Input Validation: Don't do anything if the box is empty
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return

    # Give the user immediate visual feedback that the scan has started
    result_label.configure(text="Analyzing...", text_color="gray")
    root.update()

    # Step A: Cache Check (Speed Optimization)
    # Check if we've analyzed this exact URL before to save CPU cycles
    db_status = db_manager.check_url_in_db(url)
    if db_status == "Phishing":
        result_label.configure(text="🛑 BLOCKED: Found in Phishing Database!", text_color="#ff474c")
        return
    elif db_status == "Safe":
        result_label.configure(text="✅ SAFE: Found in Safe Database.", text_color="#2ecc71")
        return

    # Step B: AI Analysis
    if model is None:
        messagebox.showerror("Error", "AI Model is offline. Did you train it first?")
        return

    # Dissect the URL into the 98 structural columns
    features_df = extract_features(url)

    # Pass the data to the Random Forest. .predict() returns an array, we take the first item [0]
    prediction = model.predict(features_df)[0]

    # Step C: Output Result & Update Database Cache
    # In dataset2.csv, the 'phishing' column uses 1 for Malicious and 0 for Safe.
    if prediction == 1:
        result_label.configure(text="⚠️ WARNING: AI Detected Phishing Link!", text_color="#ff474c")
        db_manager.log_url(url, "Phishing")
    else:
        result_label.configure(text="✅ SAFE: AI detected no immediate threats.", text_color="#2ecc71")
        db_manager.log_url(url, "Safe")


# --- 4. GRAPHICAL USER INTERFACE (GUI) SETUP ---
root = ctk.CTk()
root.title("Phishing Link Detector - BSc Cyber Security")
root.geometry("600x350")

# The main frame acts as a container to give padding and structure to the elements inside it
frame = ctk.CTkFrame(master=root)
frame.pack(pady=20, padx=20, fill="both", expand=True)

# Application Titles
title_label = ctk.CTkLabel(master=frame, text="Phishing Link Analyzer", font=("Roboto", 24, "bold"))
title_label.pack(pady=(20, 5))

subtitle_label = ctk.CTkLabel(master=frame, text="Powered by Machine Learning", font=("Roboto", 12), text_color="gray")
subtitle_label.pack(pady=(0, 20))

# The text box where the user pastes the suspicious link
url_entry = ctk.CTkEntry(master=frame, placeholder_text="Paste suspicious URL here...", width=400, height=40,
                         font=("Roboto", 14))
url_entry.pack(pady=10)

# The trigger button. The 'command' argument links it directly to our analyze_url function above
analyze_button = ctk.CTkButton(master=frame, text="Analyze Link", command=analyze_url, height=40,
                               font=("Roboto", 14, "bold"))
analyze_button.pack(pady=15)

# The dynamic text label that changes based on the AI's verdict
result_label = ctk.CTkLabel(master=frame, text="Ready to scan.", font=("Roboto", 16, "bold"))
result_label.pack(pady=(10, 20))

# Starts the Tkinter event loop, keeping the window open and listening for clicks
root.mainloop()