import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)


# Path to the dataset we downloaded from Kaggle.
# The dataset contains:
#   text_combined => the email text
#   label         => 1 for phishing, 0 for legitimate
DATASET_PATH = "data/training_dataset/phishing_email.csv"


# Directory where we will save the trained model.
MODEL_DIR = "models"

# The final trained model will be saved here.
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")


def load_dataset():
    """
    Load the phishing email dataset and separate it into
    input data (X) and target labels (y).

    X = email text
    y = 0 or 1 indicating whether the email is legitimate
        or phishing.
    """

    print("Reading dataset...")

    # Read the CSV file using pandas.
    df = pd.read_csv(DATASET_PATH)

    # Some rows may have missing email text or labels.
    # We cannot train the model on those rows, so remove them.
    df = df.dropna(subset=["text_combined", "label"])

    # X contains the actual email text that the model will learn from.
    X = df["text_combined"]

    # y contains the correct answer for each email.
    # 0 = legitimate
    # 1 = phishing
    y = df["label"]

    return X, y


def train_model(X_train, y_train):
    """
    Create and train our machine-learning pipeline.

    The pipeline has two main stages:

        Email text
            ↓
        TF-IDF
            ↓
        Logistic Regression
            ↓
        Phishing / Legitimate

    TF-IDF converts text into numbers that the ML algorithm
    can understand.

    Logistic Regression then learns patterns in those numbers
    and uses them to classify emails.
    """

    # Pipeline allows us to combine multiple ML steps together.
    #
    # This is useful because TF-IDF and Logistic Regression
    # need to be used in the same order during both training
    # and prediction.
    pipeline = Pipeline([
        
        # STEP 1: Convert email text into numerical features
        (
            "tfidf",
            TfidfVectorizer(
                # Convert all text to lowercase.
                lowercase=True,

                # Ignore common English words such as
                # "the", "is", "and", etc.
                stop_words="english",

                # Limit the vocabulary to at most 100,000 features.
                # This prevents the model from becoming unnecessarily
                # large while still giving it plenty of information.
                max_features=100000,

                # Use both individual words and pairs of words.
                #
                # (1, 2) means:
                #   1-word features -> "verify"
                #   2-word features -> "verify account"
                #
                # Two-word combinations can be useful for detecting
                # phishing phrases.
                ngram_range=(1, 2)
            )
        ),

        # STEP 2: Train the classification algorithm
        (
            "classifier",
            LogisticRegression(
                # Give the algorithm enough iterations to converge.
                max_iter=1000,

                # Makes the training result reproducible.
                random_state=42
            )
        )
    ])

    print("Fitting TF-IDF and Logistic Regression...")

    # Train both parts of the pipeline.
    #
    # First TF-IDF learns how to represent the text.
    # Then Logistic Regression learns how those features
    # relate to phishing and legitimate emails.
    pipeline.fit(X_train, y_train)

    return pipeline


def evaluate_model(model, X_test, y_test):
    """
    Evaluate the trained model using emails it has never
    seen during training.

    This gives us an idea of how well the model performs
    on unseen emails.
    """

    # Ask the model to predict whether each test email
    # is phishing (1) or legitimate (0).
    predictions = model.predict(X_test)

    # Calculate several different performance metrics.

    # Percentage of all predictions that were correct.
    accuracy = accuracy_score(y_test, predictions)

    # Of all emails predicted as phishing, how many
    # were actually phishing?
    precision = precision_score(y_test, predictions)

    # Of all actual phishing emails, how many did
    # our model successfully detect?
    recall = recall_score(y_test, predictions)

    # F1 combines precision and recall into one score.
    f1 = f1_score(y_test, predictions)

    print("\nModel Performance")
    print("-----------------")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    # This gives us a more detailed breakdown of
    # performance for both classes.
    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_test, predictions))

    # Confusion matrix shows:
    #
    # True Negative  -> legitimate correctly identified
    # False Positive  -> legitimate incorrectly marked phishing
    # False Negative  -> phishing incorrectly marked legitimate
    # True Positive   -> phishing correctly identified
    print("Confusion Matrix")
    print("----------------")
    print(confusion_matrix(y_test, predictions))


def save_model(model):
    """
    Save the trained pipeline to disk.

    We save the entire pipeline rather than just the
    Logistic Regression classifier because the TF-IDF
    vectorizer is also needed when we make predictions later.
    """

    # Create the models directory if it does not already exist.
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save the complete trained pipeline.
    joblib.dump(model, MODEL_PATH)

    print(f"\nModel saved to: {MODEL_PATH}")


def main():
    """
    Main training process.

    This function controls the complete workflow:

        1. Load dataset
        2. Split dataset
        3. Train model
        4. Evaluate model
        5. Save model
    """

    print("Loading dataset...")

    # Load the dataset
    X, y = load_dataset()

    print(f"Total emails: {len(X)}")
    print(f"Phishing: {(y == 1).sum()}")
    print(f"Legitimate: {(y == 0).sum()}")

    # 2. Split the dataset
    # 80% of the emails will be used for training.
    # 20% will be kept aside for testing.
    #
    # The model does NOT see the test emails during training.
    # This allows us to evaluate how well it works on unseen data.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,

        # 20% of the dataset goes to testing.
        test_size=0.2,

        # Makes the split reproducible.
        random_state=42,

        # Keeps roughly the same phishing/legitimate ratio
        # in both the training and testing sets.
        stratify=y
    )

    print(f"\nTraining emails: {len(X_train)}")
    print(f"Testing emails:  {len(X_test)}")

    print("\nTraining model...")

    model = train_model(X_train, y_train)

    print("Training complete.")

    # Evaluate the model
    evaluate_model(model, X_test, y_test)

    save_model(model)


if __name__ == "__main__":
    main()

