#!/bin/bash

echo "Running data preprocessing..."
python3 data_preprocessing.py || { echo "Step 1 failed"; exit 1; }

echo "Running feature engineering..."
python3 feature_engineering.py || { echo "Step 2 failed"; exit 1; }

echo "Running anomaly detection..."
python3 anomaly_detection.py || { echo "Step 3 failed"; exit 1; }

echo "Running visualization..."
python3 visualization.py || { echo "Step 4 failed"; exit 1; }

echo "Running scatterness...."
python3 scatterplot.py || { echo "Step 5 failed"; exit 1; } 

echo "All steps completed successfully!"
