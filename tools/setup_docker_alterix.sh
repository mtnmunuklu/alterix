#!/bin/bash

# Step 1: Build Docker image
docker build -t alterix -f ../Dockerfile

# Step 2: Prepare Sigma rules and configuration file
rules_directory="/path/to/rules"
config_file="/path/to/config"

# Step 3: Start Docker container and mount an output directory
output_directory="/path/to/output"  # Yerel makinedeki bir dizin
docker run -d --name alterix -v "$rules_directory":/rules -v "$config_file":/config -v "$output_directory":/output alterix