import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from joblib import dump


# read the csv file for data training.
data = pd.read_csv("/home/amy/Desktop/test/cleaned_pdf_data.csv")
data = data.select_dtypes(include=['number'])
data = data.fillna(0)
class_counts = data['Class'].value_counts()
print("Class distribution in the dataset:")
print(class_counts)

# x is features y is target
X = data.drop(columns=['Class'])
y = data['Class']

# Split data into training and testing sets.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42)
rf_model = RandomForestClassifier(random_state=42)
gb_model = GradientBoostingClassifier(random_state=42)

# Train Random Forest model
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)

# Train Gradient Boosting model
gb_model.fit(X_train, y_train)
gb_preds = gb_model.predict(X_test)

# model and metric evaluation
def evaluate_model(predictions, labels):
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions)
    recall = recall_score(labels, predictions)
    f1 = f1_score(labels, predictions)
    return accuracy, precision, recall, f1

# Random Forest model
rf_accuracy, rf_precision, rf_recall, rf_f1 = evaluate_model(rf_preds, y_test)
print("Random Forest Performance:")
print(f"Accuracy: {rf_accuracy:.4f}")
print(f"Precision: {rf_precision:.4f}")
print(f"Recall: {rf_recall:.4f}")
print(f"F1 Score: {rf_f1:.4f}")

# Gradient Boosting model
gb_accuracy, gb_precision, gb_recall, gb_f1 = evaluate_model(gb_preds, y_test)
print("\nGradient Boosting Performance:")
print(f"Accuracy: {gb_accuracy:.4f}")
print(f"Precision: {gb_precision:.4f}")
print(f"Recall: {gb_recall:.4f}")
print(f"F1 Score: {gb_f1:.4f}")
dump(rf_model, 'pdf_malware_classifier_rf.joblib')
print("Model saved successfully!")

