import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os


def train_and_save_model():
    """
    Loads the phishing dataset, filters for structural (lexical) features,
    trains a Random Forest machine learning model, evaluates its accuracy,
    and saves both the model and its required features to disk.
    """
    print("Loading the new dataset (dataset2.csv)...")

    # os.path.join ensures the file path works perfectly on Windows, Mac, and Linux
    data_path = os.path.join('data', 'dataset2.csv')

    # Safety check: Prevent a crash if the user forgot to download the dataset
    if not os.path.exists(data_path):
        print(f"Error: Could not find {data_path}. Please move dataset2.csv into the data folder.")
        return

    # Load the CSV data into a Pandas DataFrame
    df = pd.read_csv(data_path)

    # 1. Feature Engineering: Isolate the purely structural (lexical) features.
    # The following features require slow external network calls (like asking a DNS server
    # for the domain's age). For a fast, real-time GUI, we drop these and rely only on
    # the physical structure of the URL text itself.
    network_features = [
        'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation',
        'time_domain_expiration', 'qty_ip_resolved', 'qty_nameservers',
        'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate',
        'qty_redirects', 'url_google_index', 'domain_google_index', 'url_shortened'
    ]

    # 2. Separate Inputs (X) from the Answer Key (y)
    # We drop the slow network features AND the 'phishing' column from X.
    X = df.drop(columns=network_features + ['phishing'])

    # 'phishing' is our target label (1 = Phishing, 0 = Safe).
    y = df['phishing']

    # 3. Save the Feature Map
    # CRITICAL: A machine learning model requires data to be fed to it in the EXACT same
    # order it was trained on. By saving `list(X.columns)`, we give our GUI a "map" so it
    # knows exactly which 98 features to generate and in what order.
    joblib.dump(list(X.columns), 'model_features.pkl')

    # 4. Data Splitting
    # test_size=0.2 means 80% of the 88,000 URLs are used to teach the AI,
    # and 20% are held back to test it on data it has never seen before.
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 5. Initialize and Train the Model
    # Random Forest builds 100 different decision trees and averages their guesses.
    # n_jobs=-1 tells Python to use all available CPU cores to train faster.
    print("Training the Random Forest model on Lexical Features...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # 6. Evaluate Model Accuracy
    # Predict the answers for our 20% test data and compare them against the real answers (y_test).
    print("Evaluating model accuracy...")
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\n--- NEW MODEL RESULTS ---")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("\nDetailed Report:")
    # classification_report shows precision (how many flagged were actually phishing)
    # and recall (how many phishing links did it accidentally let through).
    print(classification_report(y_test, predictions, target_names=['Safe (0)', 'Phishing (1)']))

    # 7. Serialize the Model
    # Save the trained brain to a file so the GUI app can use it instantly without retraining.
    print("\nSaving the trained model...")
    joblib.dump(model, 'phishing_model_v2.pkl')
    print("Model saved successfully as 'phishing_model_v2.pkl'!")


# Execute training only if this file is run directly
if __name__ == "__main__":
    train_and_save_model()