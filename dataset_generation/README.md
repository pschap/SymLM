# Dataset Generation

Instructions about how to generate dataset from binaries.

## Table of contents

- [Dataset Generation](#dataset-generation)
  - [Table of contents](#table-of-contents)
  - [Setup](#setup)
  - [Dataset Preparation](#dataset-preparation)
    - [Binary Example](#binary-example)
    - [Parameters](#parameters)
    - [Sample Dataset](#sample-dataset)
  - [Dataset Encoding](#dataset-encoding)
    - [Vocabulary Generation](#vocabulary-generation)
    - [Dataset Binarization](#dataset-binarization)

## Setup

* Ghidra installation

For dataset generation, we use Ghidra to parse the binary. Therefore, you need to install Ghidra first (Our scripts have been tested on Ghidra 10.1.2). For more details, please refer to [Ghidra](https://ghidra-sre.org/).

## Dataset Preparation

The dataset generation script is [`run.sh`](run.sh). Before running it, please set the following variables:

```bash executable
GHIDRA_PROJECT_PATH=''            # Path to Ghidra Project
GHIDRA_PROJECT_NAME=''            # Name of Ghidra Project
ICFG_OUTPUT_DIR=''                # Path to ICFG Output Directory
ICFG_OUTPUT_NAME=''               # Name of ICFG Output File
INPUT_BINARY=''                   # Path to Binary
IS_PORTABLE_EXECUTABLE=false      # Portable Executable Binaries
SYMBOL_PATH=''                    # Debugging Information (PDB File)
```

Then simply run the script with:

```bash
cd dataset_generation # make sure you are in the dataset_generation folder
bash run.sh
```

Alternatively, a dataset can be generated for a batch of binaries using the script ['run_batch.sh](run_batch.sh). To use this script, first
create a comma-delimited text file, where each line is of the following format.

ICFG_OUTPUT_DIR,ICFG_OUTPUT_NAME,INPUT_BINARY,IS_PORTABLE_EXECUTABLE,SYMBOL_PATH

The last two fields of each line are optional. Then, using this text file, the script can be run as follows:

```bash
cd dataset_generation
bash run_batch.sh BATCH_FILE GHIDRA_PROJECT_PATH GHIDRA_PROJECT_NAME
```

The script contains two parts: (1) inter-procedural CFG generation and (2) dataset preparation. For ICFG generation, we use Ghidra script `get_calling_context.py`. For dataset prepartion, we developed `prepare_dataset.py`.
