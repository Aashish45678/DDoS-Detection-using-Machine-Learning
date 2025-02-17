import os
from flask import Flask, render_template, request, jsonify
import pandas as pd
from feature_extraction import calculate_features_with_threading
import joblib  # For loading models and scalers
from sklearn.ensemble import RandomForestClassifier  # If model is RandomForest
from sklearn.preprocessing import StandardScaler  # If scaler is StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
import tensorflow as tf
from tensorflow.keras.models import load_model
import numpy as np

app = Flask(__name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'csv'}

# Load the trained model and scaler
# model = joblib.load('./model_and_scaler/ddos_attack_detection_model.joblib')
# scaler = joblib.load('./model_and_scaler/feature_scaler.joblib')
model = load_model('./LSTM_Model_Training_Without_Sampling/All_lstm_ddos_model.h5')
scaler = joblib.load('./LSTM_Model_Training_Without_Sampling/All_scaler.pkl')

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def preprocess_and_predict(file_path, is_pcap=False):
    """
    Function to preprocess data (from PCAP/PCAPNG or CSV), make predictions,
    and return results as a DataFrame.
    """
    if is_pcap:
        print("Extracting features from PCAP...")
        features_df = calculate_features_with_threading(file_path)
        print(f"Extracted features:\n{features_df.head()}")

    else:
        # Load CSV directly
        features_df = pd.read_csv(file_path)
        test_df = features_df
    
    # Preprocess and clean data
    # features_df.columns = features_df.columns.str.strip()  # Clean column names
    # features_df = features_df.dropna()  # Remove null values
    # features_df = features_df.replace([float('inf'), float('-inf')], pd.NA).dropna()  # Handle inf/-inf

    # # Drop non-numeric or unnecessary columns
    # data_f2 = features_df.drop(['src_ip', 'dst_ip', 'src_port', 'protocol'], axis=1, errors='ignore')
    
    # Remove the spaces before the column names
    test_df.columns = test_df.columns.str.strip()

    ## Removing the null values
    data2_f=test_df.dropna()

    # Replace inf and -inf with NaN in the DataFrame
    data2_f = data2_f.replace([float('inf'), float('-inf')], pd.NA)

    # Check for NaN values
    null_values = data2_f.isnull().sum()

    # print(f"Features before scaling:\n{data_f2.head()}")
    
    # Ensure dataset has the required features
    X_new = data2_f.drop(['src_ip', 'dst_ip', 'src_port','protocol'],axis=1)

    # Normalize using the previously saved scaler
    X_new_scaled = scaler.transform(X_new)
    
    def create_sequences(X, time_steps=10):
        Xs = []
        for i in range(len(X) - time_steps):
            Xs.append(X[i : i + time_steps])
        return np.array(Xs)

    X_new_seq = create_sequences(X_new_scaled, time_steps=10)

    predictions = (model.predict(X_new_seq) > 0.5).astype("int32")

    probabilities = model.predict(X_new_scaled).flatten()  # Get probabilities
    
    # Create results DataFrame
    results = pd.DataFrame({
        'Prediction': ['DDoS' if p == 1 else 'Benign' for p in predictions],
        'Confidence': probabilities,
        'Original_Source_IP': features_df.get('src_ip', ''),
        'Original_Dest_IP': features_df.get('dst_ip', ''),
        'Original_Protocol': features_df.get('protocol', '')
    })

    return results

@app.route('/')
def index():
    """Render the homepage."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Handle file uploads and perform feature extraction and prediction.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .pcap, .pcapng, and .csv are allowed.'}), 400
    
    file_path = f"./uploads/{file.filename}"
    file.save(file_path)

    is_pcap = file.filename.endswith(('.pcap', '.pcapng'))
    try:
        # Predict using extracted or existing features
        results = preprocess_and_predict(file_path, is_pcap=is_pcap)
        summary = results['Prediction'].value_counts().to_dict()  # Summary stats for display

        # Return the first prediction for simplicity
        first_classification = results.iloc[0]['Prediction']
        first_confidence = results.iloc[0]['Confidence']
        return jsonify({
            'classification': first_classification,
            'confidence': round(first_confidence, 2),
            'summary': summary,
            'details': results.to_dict(orient='records')
        })
    except Exception as e:
        return jsonify({'error': f'Error during prediction: {str(e)}'}), 500
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == '__main__':
    # Ensure uploads directory exists
    os.makedirs('./uploads', exist_ok=True)
    app.run(debug=True)