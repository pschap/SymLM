#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo Usage: run_batch.sh BATCH_FILE GHIDRA_PROJECT_PATH GHIDRA_PROJECT_NAME
    exit
fi

BATCH_FILE=$1
GHIDRA_PROJECT_PATH=$2
GHIDRA_PROJECT_NAME=$3

echo Starting batch...

i=1
while IFS="," read -r -a args; do
    
    if [ "${#args[@]}" -lt 3 ] || [ "${#args[@]}" -gt 5 ]; then
        echo Cannot parse line $i of $BATCH_FILE. Skipping batch item...
        continue
    fi

    ICFG_OUTPUT_DIR=${args[0]}
    ICFG_OUTPUT_NAME=${args[1]}
    INPUT_BINARY=${args[2]}
    
    IS_PORTABLE_EXECUTABLE=false
    if [ "${#args[@]}" -ge 4 ]; then
        if [ "${args[3]}" == "true" ]; then
            IS_PORTABLE_EXECUTABLE=true
        fi
    fi

    SYMBOL_PATH=''
    if [ "${#args[@]}" == 5 ]; then
        SYMBOL_PATH=${args[4]}
    fi

    python3.8 get_calling_context.py \
        --icfg_dir $ICFG_OUTPUT_DIR \
        --icfg_name $ICFG_OUTPUT_NAME \
        --ghidra_project_path $GHIDRA_PROJECT_PATH \
        --ghidra_project_name $GHIDRA_PROJECT_NAME \
        --input_binary $INPUT_BINARY \
        --is_portable_executable $IS_PORTABLE_EXECUTABLE \
        --symbol_path $SYMBOL_PATH

    i=$((i+1))

done < $BATCH_FILE

echo Ending batch...
