from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse,RedirectResponse
from fastapi.templating import Jinja2Templates
import os
import fitz  # PyMuPDF
import hashlib
import requests
import joblib
import re
from datetime import datetime
import sqlite3

app = FastAPI()

# Directory to store uploaded files
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)




templates = Jinja2Templates(directory="templates")


API_KEY = 'add api key here'
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report"


model = joblib.load("/home/amy/Desktop/test/pdf_malware_classifier_rf.joblib")  # Update with the actual path to your model file

# database storage
conn = sqlite3.connect("pdf_analysis.db")
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS pdf_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT,
    upload_timestamp TEXT,
    main_file_hash TEXT,
    result TEXT
)
''')
conn.commit()

def generate_hash(file_bytes, hash_type="md5"):
    hash_func = hashlib.md5() if hash_type == "md5" else hashlib.sha256()
    hash_func.update(file_bytes)
    return hash_func.hexdigest()

# check VT hash db
def check_virustotal(file_hash):
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(VIRUSTOTAL_URL, params=params)
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            positives = result.get('positives', 0)
            total = result.get('total', 0)
            return f"{positives}/{total} detections"
        else:
            return "No matching scan found in VirusTotal"
    else:
        return f"Error: {response.status_code} - {response.reason}"

# Function to extract embedded files and check them with VirusTotal
def extract_and_check_embedded_files(pdf_file_path):
    pdf_document = fitz.open(pdf_file_path)
    embedded_files_info = []

    for i in range(pdf_document.xref_length()):
        try:
            obj_str = pdf_document.xref_object(i)
            if "/EmbeddedFile" in obj_str:
                stream = pdf_document.xref_stream(i)
                if stream:
                    md5_hash = generate_hash(stream, "md5")
                    sha256_hash = generate_hash(stream, "sha256")
                    virus_total_result = check_virustotal(sha256_hash)
                    embedded_file_info = {
                        "xref_index": i,
                        "file_size": len(stream),
                        "md5_hash": md5_hash,
                        "sha256_hash": sha256_hash,
                        "VirusTotal Result": virus_total_result
                    }
                    embedded_files_info.append(embedded_file_info)
        except Exception:
            continue

    pdf_document.close()
    return embedded_files_info

# Function to extract PDF features including Colors, obj, endobj, header
def extract_pdf_features(pdf_file_path):
    pdf_document = fitz.open(pdf_file_path)
    
    features = {
        "pdfsize": os.path.getsize(pdf_file_path),
        "metadata size": len(pdf_document.metadata),
        "pages": pdf_document.page_count,
        "xref Length": pdf_document.xref_length(),
        "title characters": len(pdf_document.metadata.get('title', '')),
        "isEncrypted": int(pdf_document.is_encrypted),
        "embedded files": 0,
        "images": 0,
        "text": 0,  # Use binary (0 or 1) for text
        "header": 0,  # 0 if invalid
        "obj": 0,
        "endobj": 0,
        "stream": 0,
        "endstream": 0,
        "xref": 0,
        "trailer": 0,
        "startxref": 0,
        "pageno":0,
        "encrypt":0,
        "ObjStm": 0,
        "JS": 0,
        "Javascript": 0,
        "AA": 0,
        "OpenAction": 0,
        "Acroform": 0,
        "JBIG2Decode": 0,
        "RichMedia": 0,
        "launch": 0,
        "EmbeddedFile": 0,
        "XFA": 0,
        "Colors": 0
    }

    for page_num in range(pdf_document.page_count):
        page = pdf_document.load_page(page_num)
        page_text = page.get_text("text")
        
        if page_text:
            features["text"] = 1  # Set to 1 if text is found
        
        features["images"] += len(page.get_images(full=True))

        if 'stream' in page_text:
            features["stream"] += 1
        if 'endstream' in page_text:
            features["endstream"] += 1

    for i in range(pdf_document.xref_length()):
        try:
            obj_str = pdf_document.xref_object(i)
            if "obj" in obj_str:
                features["obj"] += 1
            if "endobj" in obj_str:
                features["endobj"] += 1
            if "/JS" in obj_str or "/JavaScript" in obj_str:
                features["JS"] += 1
                features["Javascript"] += 1
            if "/Launch" in obj_str:
                features["launch"] += 1
            if "/OpenAction" in obj_str:
                features["OpenAction"] += 1
            if "/Acroform" in obj_str:
                features["Acroform"] += 1
            if "/JBIG2Decode" in obj_str:
                features["JBIG2Decode"] += 1
            if "/RichMedia" in obj_str:
                features["RichMedia"] += 1
            if "/AA" in obj_str:
                features["AA"] += 1
            if "/EmbeddedFile" in obj_str:
                features["EmbeddedFile"] += 1
            if "xref" in obj_str:
                features["xref"] += 1
            if "startxref" in obj_str:
                features["startxref"] += 1
            if "trailer" in obj_str:
                features["trailer"] += 1
            if "/ObjStm" in obj_str:
                features["ObjStm"] += 1
            if "/XFA" in obj_str:
                features["XFA"] += 1
            if "/Color" in obj_str:
                features["Colors"] += 1
        except Exception:
            continue

    # Set the header field based on validity
    with open(pdf_file_path, 'rb') as f:
        header = f.read(8)
        if re.match(rb"%PDF-\d+\.\d+", header):
            features['header'] = 1  # Set to 1 if valid format
        else:
            features['header'] = 0

    pdf_document.close()
    return features

# Prediction function
def predict_pdf_class(features):
    feature_order = [
        'pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters',
        'isEncrypted', 'embedded files', 'images', 'text', 'header', 'obj', 
        'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', 
        'pageno', 'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction', 
        'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 
        'XFA', 'Colors'
    ]
    
    feature_values = [features[key] for key in feature_order]
    prediction = model.predict([feature_values])
    return prediction[0]

# Upload and Prediction Route
@app.post("/upload/")
async def upload_pdf(request: Request, file: UploadFile = File(...)):
    try:
        if not file.filename:
            return {"error": "No file selected."}

        file_location = f"{UPLOAD_DIR}/{file.filename}"
        with open(file_location, "wb+") as file_object:
            file_object.write(await file.read())

        main_file_hash = generate_hash(open(file_location, "rb").read(), "sha256")
        virustotal_result = check_virustotal(main_file_hash)

        embedded_files_info = extract_and_check_embedded_files(file_location)
        pdf_features = extract_pdf_features(file_location)
        model_prediction = predict_pdf_class(pdf_features)
        
        final_result = "Malicious" if model_prediction == 1 else "Benign"

        # database storage
        timestamp = datetime.now().isoformat()
        c.execute("INSERT INTO pdf_records (file_name, upload_timestamp, main_file_hash, result) VALUES (?, ?, ?, ?)",
                  (file.filename, timestamp, main_file_hash, final_result))
        conn.commit()
        os.remove(file_location)

        return templates.TemplateResponse("summary.html", {
            "request": request,
            "embedded_files_info": embedded_files_info,
            "pdf_features": pdf_features,
            "filename": file.filename,
            "predicted_class": model_prediction,
            "main_file_hash": main_file_hash,
            "virustotal_pdf_result": virustotal_result,
            "final_result": final_result
        })
    except Exception as e:
        return {"error": str(e)}
# Home page route
@app.get("/", response_class=HTMLResponse)
async def main(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})


