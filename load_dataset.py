import os
import pandas as pd
import kagglehub

# 1. Define your target local directory
target_directory = "data/training_dataset"

# 2. Download the dataset and force it into your specific folder
downloaded_path = kagglehub.dataset_download(
    "naserabdullahalam/phishing-email-dataset", 
    output_dir=target_directory
)
print(f"Dataset successfully saved to: {downloaded_path}")

# 3. List the files inside your new folder to find the exact CSV name
files = os.listdir(downloaded_path)
print(f"Files found in folder: {files}")

# 4. Load it into Pandas from your local folder
# (Replace 'phishing_email.csv' with the actual filename printed in step 3)
csv_filename = "phishing_email.csv" 
local_csv_path = os.path.join(downloaded_path, csv_filename)

if os.path.exists(local_csv_path):
    df = pd.read_csv(local_csv_path)
    print("\nFirst 5 records:\n", df.head())
else:
    print(f"\nCould not find '{csv_filename}'. Please check the printed file list above.")
