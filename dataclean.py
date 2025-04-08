import pandas as pd

# Step 1.1: Load CSV File
df = pd.read_csv("network_features.csv")

# Step 1.2: Display first few rows
print("First 5 rows of data:")
print(df.head())

# Step 1.3: Check Data Types and Missing Values
print("\nDataset Info:")
print(df.info())

print("\nMissing Values Count:")
print(df.isnull().sum())

# Convert timestamp to datetime if it's not already
if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
    df["timestamp"] = pd.to_datetime(df["timestamp"])

# Step 1.4: Get Basic Statistics
print("\nStatistical Summary:")
print(df.describe())

# Step 1.5: Detect and Remove Duplicates
duplicates = df.duplicated().sum()
print(f"\nNumber of Duplicates: {duplicates}")

if duplicates > 0:
    df.drop_duplicates(inplace=True)
    print("Duplicates removed.")

# Step 1.6: Save Cleaned Data
df.to_csv("cleaned_network_features.csv", index=False)
print("\n✅ Data Cleaning Complete! Cleaned data saved as 'cleaned_network_features.csv'.")
