#!/usr/bin/env python3
"""
repair_manifest.py

Removes null bytes (\x00) from the dataset_manifest.csv which can occur 
if the system experiences a power interruption while writing the file.
"""

import os

MANIFEST_PATH = '/data/flows/metadata/dataset_manifest.csv'

def repair():
    if not os.path.exists(MANIFEST_PATH):
        print(f"Error: {MANIFEST_PATH} not found.")
        return

    print(f"Reading {MANIFEST_PATH}...")
    with open(MANIFEST_PATH, 'rb') as f:
        data = f.read()

    null_count = data.count(b'\x00')
    if null_count == 0:
        print("No null bytes found. File is clean!")
        return

    print(f"Found {null_count} null bytes. Cleaning...")
    clean_data = data.replace(b'\x00', b'')

    with open(MANIFEST_PATH, 'wb') as f:
        f.write(clean_data)

    print(f"Success! File size: {len(data)} -> {len(clean_data)} bytes.")

if __name__ == "__main__":
    repair()
