#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo Usage: run_batch.sh BATCH_FILE GHIDRA_PROJECT_PATH GHIDRA_PROJECT_NAME TOPK
    exit
fi

BATCH_FILE=$1
GHIDRA_PROJECT_PATH=$2
GHIDRA_PROJECT_NAME=$3
TOPK=$4

echo Starting batch...

i=1
while IFS="," read -r -a args; do
    
    if [ "${#args[@]}" -lt 5 ] || [ "${#args[@]}" -gt 7 ]; then
        echo Cannot parse line $i of $BATCH_FILE. Skipping batch item...
        continue
    fi

    ICFG_OUTPUT_DIR=${args[0]}
    ICFG_OUTPUT_NAME=${args[1]}
    ICFG_DIR="$ICFG_OUTPUT_DIR"/"$ICFG_OUTPUT_NAME"
    INPUT_BINARY=${args[2]}
    DATASET_OUTPUT_DIR=${args[3]}
    BINARY_ARCHITECTURE=${args[4]}
    
    IS_PORTABLE_EXECUTABLE=false
    if [ "${#args[@]}" -ge 6 ]; then
        if [ "${args[5]}" == "true" ]; then
            IS_PORTABLE_EXECUTABLE=true
        fi
    fi

    SYMBOL_PATH=''
    if [ "${#args[@]}" == 7 ]; then
        SYMBOL_PATH=${args[6]}
    fi

    if [ "$IS_PORTABLE_EXECUTABLE" = true ]; then
        python3.8 get_calling_context.py \
            --icfg_dir $ICFG_OUTPUT_DIR \
            --icfg_name $ICFG_OUTPUT_NAME \
            --ghidra_project_path $GHIDRA_PROJECT_PATH \
            --ghidra_project_name $GHIDRA_PROJECT_NAME \
            --input_binary $INPUT_BINARY \
            --is_portable_executable $IS_PORTABLE_EXECUTABLE \
            --symbol_path $SYMBOL_PATH

        python3.8 prepare_dataset.py \
            --output_dir $DATASET_OUTPUT_DIR \
            --input_binary $INPUT_BINARY \
            --icfg_dir $ICFG_DIR \
            --is_portable_executable $IS_PORTABLE_EXECUTABLE \
            --symbol_path $SYMBOL_PATH \
            --arch $BINARY_ARCHITECTURE \
            --top_k $TOPK
    else
        python3.8 get_calling_context.py \
            --icfg_dir $ICFG_OUTPUT_DIR \
            --icfg_name $ICFG_OUTPUT_NAME \
            --ghidra_project_path $GHIDRA_PROJECT_PATH \
            --ghidra_project_name $GHIDRA_PROJECT_NAME \
            --input_binary $INPUT_BINARY 

        python3.8 prepare_dataset.py \
            --output_dir $DATASET_OUTPUT_DIR \
            --input_binary $INPUT_BINARY \
            --icfg_dir $ICFG_DIR \
            --arch $BINARY_ARCHITECTURE \
            --top_k $TOPK
    fi

    i=$((i+1))

done < $BATCH_FILE

echo Ending batch...
