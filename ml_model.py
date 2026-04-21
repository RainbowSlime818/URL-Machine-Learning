import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os


def train_and_save_model():
    print("Loading dataset...")
    # Ensure the path matches where you put the CSV file
    data_path = 'data/dataset.csv'

    if not os.path.exists(data_path):
        print(f"Error: Could not find the dataset at {data_path}")
        return

    # Load the data
    df = pd.read_csv(data_path)

    # 1. Separate the Features (X) from the Target Answer (y)
    # We drop the 'index' column because it's just ID numbers, not a feature
    # We drop 'Result' because that is the answer we want the AI to predict
    X = df.drop(columns=['index', 'Result'])
    y = df['Result']

    # 2. Split the data into Training and Testing sets (80% train, 20% test)
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Initialize and Train the Random Forest Model
    print("Training the Random Forest model (this might take a few seconds)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 4. Evaluate the Model
    print("Evaluating model accuracy...")
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\n--- MODEL RESULTS ---")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("\nDetailed Report:")
    print(classification_report(y_test, predictions, target_names=['Phishing (-1)', 'Safe (1)']))

    # 5. Save the trained model so the GUI can use it without retraining
    print("\nSaving the trained model...")
    joblib.dump(model, 'phishing_model.pkl')
    print("Model saved successfully as 'phishing_model.pkl'!")


# Run the function if this script is executed directly
if __name__ == "__main__":
    train_and_save_model()