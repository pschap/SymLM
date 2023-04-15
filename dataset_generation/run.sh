#!/bin/bash

# Ghidra Project Information
GHIDRA_PROJECT_PATH='/home/../mnt/c/Ghidra'         # Path to Ghidra Project
GHIDRA_PROJECT_NAME='SymLM'                         # Name of Ghidra Project

# ICFG Output
ICFG_OUTPUT_DIR='icfg'                              # Path to ICFG Output Directory
ICFG_OUTPUT_NAME='CHIP-8.json'          # Name of ICFG Output File

# Input Binary
INPUT_BINARY='binaries/CHIP-8.exe'

# (Optional) For Windows/Portable Executable Binaries
IS_PORTABLE_EXECUTABLE=true                 # Portable Executable Binaries
SYMBOL_PATH='pdb/CHIP-8.pdb'                 # Debugging Information (PDB File)

# Generate the ICFG
python3.8 get_calling_context.py \
    --icfg_dir $ICFG_OUTPUT_DIR \
    --icfg_name $ICFG_OUTPUT_NAME \
    --ghidra_project_path $GHIDRA_PROJECT_PATH \
    --ghidra_project_name $GHIDRA_PROJECT_NAME \
    --input_binary $INPUT_BINARY \
    --is_portable_executable $IS_PORTABLE_EXECUTABLE \
    --symbol_path $SYMBOL_PATH
