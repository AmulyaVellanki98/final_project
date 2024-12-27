import pandas as pd
import numpy as np
import re

# Load dataset
data = pd.read_csv("/home/amy/Desktop/test/PDFMalware2022.csv")

# Replace -1 and NaN in selected columns with NaN for consistency
columns_with_minus_one = [
    'pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters', 
    'isEncrypted', 'embedded files', 'images', 'text', 'header', 'obj', 
    'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', 
    'pageno', 'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction', 
    'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 
    'XFA', 'Colors'
]



# Convert 'text' column to numerical (Yes=1, No=0, unclear=0)
data['text'] = data['text'].replace({'Yes': 1, 'No': 0, 'unclear': 0})

# Process 'isEncrypted' column to binary (assuming >1 values mean encrypted)
data['isEncrypted'] = data['isEncrypted'].apply(lambda x: 1 if x > 0 else 0)

# Convert 'Class' column to binary labels for modeling
data['Class'] = data['Class'].replace({'Malicious': 1, 'Benign': 0})
data['Class'] = data['Class'].astype('Int64')  # Use 'Int64' dtype for optional NaNs handling

# Clean columns like 'JS', 'Javascript', 'AA', 'OpenAction', etc.
columns_to_clean = [
    'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform', 'JBIG2Decode', 
    'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'images', 'endstream', 'pageno'
]
for col in columns_to_clean:
    data[col] = data[col].apply(lambda x: int(re.search(r'\d+', str(x)).group()) if pd.notnull(x) and re.search(r'\d+', str(x)) else 0)

# Clean 'obj', 'endobj', 'xref', 'startxref' by keeping only numeric values or setting 0
special_columns = ['obj', 'endobj', 'xref', 'startxref']
for col in special_columns:
    data[col] = data[col].apply(lambda x: int(re.search(r'\d+', str(x)).group()) if pd.notnull(x) and re.search(r'\d+', str(x)) else 0)

# Function to check for a standard PDF header format and update in-place
def is_standard_header(header):
    header = str(header).strip()
    return 1 if re.match(r"%PDF-\d+\.\d+$", header) else 0

# Update the 'header' column to reflect whether it follows the standard format
data['header'] = data['header'].apply(is_standard_header)

# Drop rows with missing essential features like 'pdfsize' or 'metadata size'
data = data.dropna(subset=['pdfsize', 'metadata size', 'pages'])

# Save the cleaned data
data.to_csv("cleaned_pdf_data.csv", index=False)
