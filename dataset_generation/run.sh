#!/bin/bash

# Ghidra Project Information
GHIDRA_PROJECT_PATH='/home/../mnt/c/Ghidra'         # Path to Ghidra Project
GHIDRA_PROJECT_NAME='SymLM'                         # Name of Ghidra Project

# ICFG Output
ICFG_OUTPUT_DIR='icfg'                              # Path to ICFG Output Directory
ICFG_OUTPUT_NAME='ICFG_CHIP-8.json'                 # Name of ICFG Output File

# Input Binary
INPUT_BINARY='sample_binary/CHIP-8.exe'

# (Optional) For Windows/Portable Executable Binaries
IS_PORTABLE_EXECUTABLE=true                        # Portable Executable Binaries
SYMBOL_PATH='sample_pdb/CHIP-8.pdb'                # Debugging Information (PDB File)

# Dataset Preparation
DATASET_OUTPUT_DIR='sample_output'                 # Path to Dataset Output Directory
BINARY_ARCHITECTURE='x86'                          # Architecture of Binary: x86, x64, arm, mips
ICFG_DIR="$ICFG_OUTPUT_DIR"/"$ICFG_OUTPUT_NAME"    # ICFG Path
TOPK=2                                             # Take Top-K most frequent functions 

# Generate the ICFG
python3.8 get_calling_context.py \
    --icfg_dir $ICFG_OUTPUT_DIR \
    --icfg_name $ICFG_OUTPUT_NAME \
    --ghidra_project_path $GHIDRA_PROJECT_PATH \
    --ghidra_project_name $GHIDRA_PROJECT_NAME \
    --input_binary $INPUT_BINARY \
    --is_portable_executable $IS_PORTABLE_EXECUTABLE \
    --symbol_path $SYMBOL_PATH

# Generate the dataset
python3.8 prepare_dataset.py \
    --output_dir $DATASET_OUTPUT_DIR \
    --input_binary $INPUT_BINARY \
    --icfg_dir $ICFG_DIR \
    --is_portable_executable $IS_PORTABLE_EXECUTABLE \
    --symbol_path $SYMBOL_PATH \
    --arch $BINARY_ARCHITECTURE \
    --top_k $TOPK
