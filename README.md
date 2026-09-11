# Phishing Link Detector using Machine Learning

A desktop application designed to detect and classify malicious (phishing) URLs in real-time. Operating on a trained **Random Forest Classifier** that evaluates strictly lexical and structural features of URL strings, the system delivers instantaneous verdicts through a modern graphical interface without requiring external network or DNS lookups. Analyzed links are automatically indexed and cached locally via SQLite.

---

## Overview & Architecture

The application is structured into three primary components:

1. **Machine Learning Pipeline (`ml_model.py`)**
   - Ingests URL datasets (`data/dataset2.csv`).
   - Removes latency-heavy external/network-dependent attributes (such as WHOIS domain expiration, response times, SSL certificates, DNS queries, and Google index status) to enable instantaneous local evaluation.
   - Trains a `RandomForestClassifier` with 100 estimators across 98 lexical/syntactic features.
   - Serializes the trained model (`phishing_model_v2.pkl`) and ordered feature column list (`model_features.pkl`).

2. **Feature Extraction & GUI Engine (`main.py`)**
   - Built using `customtkinter` with support for OS light/dark appearance modes.
   - Deconstructs input URLs into domain, path, directory, file, and query components.
   - Generates 98 structural indicators (special character frequencies, vowel distribution, domain length, presence of raw IP addresses, embedded emails, and parameter metrics) aligned with the model's training schema.

3. **Database & Caching Layer (`db_manager.py`)**
   - Local SQLite database (`database/url_logs.db`) storing scanned URLs and classification results (`id`, `url`, `status`).
   - Utilizes parameterized queries (`?`) to prevent SQL injection vulnerabilities.
   - Provides a caching mechanism to return instant verdicts for previously analyzed URLs.

---

## Project Structure

```text
URL-Machine-Learning/
├── data/
│   ├── dataset.csv            # Baseline dataset
│   └── dataset2.csv           # Primary dataset used for model training
├── database/
│   └── url_logs.db            # Local SQLite database caching URL analysis history
├── db_manager.py              # Database interface (schema setup, logging, cache lookups)
├── ml_model.py                # Model training, feature selection, and evaluation pipeline
├── main.py                    # CustomTkinter GUI application and URL feature extractor
├── model_features.pkl         # Serialized list of the 98 required feature names
├── phishing_model.pkl         # Baseline model artifact (v1)
└── phishing_model_v2.pkl      # Production model artifact (v2)
```

---

## Key Features

- **Real-Time Lexical Analysis**: Evaluates raw URL syntax locally without incurring network latency from DNS lookups or WHOIS scraping.
- **Comprehensive Feature Set**: Measures counts of special characters (`.`, `-`, `@`, `?`, `=`, `_`, `%`, etc.), directory depth, file lengths, parameter counts, and suspicious lexical tokens.
- **Local SQLite Caching**: Skips redundant model inferences for recurring queries, instantly retrieving past verdicts.
- **Modern User Interface**: Clean desktop GUI with system theme synchronization.

---

## Installation & Setup

### Prerequisites
- Python 3.10 or higher

### Dependencies
Install the required packages using `pip`:

```bash
pip install customtkinter scikit-learn pandas joblib
```

---

## Usage

### Running the Desktop Application

Launch the main GUI:

```bash
python main.py
```

1. Enter or paste a URL into the input field.
2. Click **Analyze Link**.
3. The system checks the local cache first; if unrecorded, it extracts features, evaluates the model, logs the URL to the database, and displays:
   - `✅ SAFE: AI detected no immediate threats.`
   - `⚠️ WARNING: AI Detected Phishing Link!`

### Retraining the Model

To retrain and update the model artifacts using the primary dataset:

```bash
python ml_model.py
```

This will:
- Load `data/dataset2.csv`.
- Filter down to the 98 structural features.
- Perform an 80/20 train/test split.
- Train a Random Forest classifier across all available CPU cores (`n_jobs=-1`).
- Print evaluation metrics (accuracy, precision, recall, F1-score).
- Save updated `phishing_model_v2.pkl` and `model_features.pkl` files.
