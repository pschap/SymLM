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
cd dataset_generation
bash run.sh
```

Alternatively, a dataset can be generated for a batch of binaries using the script [`run_batch.sh`](run_batch.sh). To use this script, first
create a comma-delimited text file, where each line is of the following format.

```plaintext
ICFG_OUTPUT_DIR,ICFG_OUTPUT_NAME,INPUT_BINARY,OUTPUT_DIR,ARCHITECTURE,IS_PORTABLE_EXECUTABLE,SYMBOL_PATH
```

The last two fields of each line are optional. Then, using this text file, the script can be run as follows:

```bash
cd dataset_generation
bash run_batch.sh BATCH_FILE GHIDRA_PROJECT_PATH GHIDRA_PROJECT_NAME TOPK
```

The script contains two parts: (1) inter-procedural CFG generation and (2) dataset preparation. For ICFG generation, we use Ghidra script `get_calling_context.py`. For dataset prepartion, we developed `prepare_dataset.py`. We provide a sample text-file for processing a batch of binaries in `batch.txt1`.

The [`utils`](utils) folder contains several Python scripts containing utilities for dataset preparation. Specifically, we offer utilities for generating datasets for ELF/Linux binaries in `linux_utils.py`. Similarly, we offer utilities for generating datasets for Portable Executable/Windows binaries in `windows_utilts.py`. `dataset_utils.py` contains utility functions that are used regardless of the binary format. Functions from these scripts are called in the `prepare_dataset.py` script. None of these scripts should be used on their own.

### Binary Example

We provide sample `x64` binaries under [`sample_binary`](sample_binary). [`sample_binary/bc`](sample_binary/bc) contains two ELF binaries, while [`sample_binary/CHIP-8.exe`](sample_binary/CHIP-8.exe) is a sample portable executable binary. By running the `run_batch.sh` script with the sample batch file `batch.txt`, the generated datasets are under [`sample_output/`](sample_output/) and the directory structure for each binary is:

```plaintext
sample_output/bc/
├── caller1 # folder containing sequences of the first caller
│   ├── input.arch_emb
│   ├── input.byte1
│   ├── input.byte2
│   ├── input.byte3
│   ├── input.byte4
│   ├── input.inst_pos_emb
│   ├── input.op_pos_emb
│   └── input.static
├── caller2 
│   ├── input.arch_emb
│   ├── input.byte1
│   ├── input.byte2
│   ├── input.byte3
│   ├── input.byte4
│   ├── input.inst_pos_emb
│   ├── input.op_pos_emb
│   └── input.static
├── external_callee1 # folder containing external callee names of the first external callee
│   └── input.label # external callee names are used for query external function embedding lookup table
├── external_callee2
│   └── input.label
├── internal_callee1 # folder containing sequences of the first internal callee
│   ├── input.arch_emb
│   ├── input.byte1
│   ├── input.byte2
│   ├── input.byte3
│   ├── input.byte4
│   ├── input.inst_pos_emb
│   ├── input.op_pos_emb
│   └── input.static
├── internal_callee2
│   ├── input.arch_emb
│   ├── input.byte1
│   ├── input.byte2
│   ├── input.byte3
│   ├── input.byte4
│   ├── input.inst_pos_emb
│   ├── input.op_pos_emb
│   └── input.static
└── self    # folder containing sequences of function instructions
    ├── input.arch_emb
    ├── input.byte1
    ├── input.byte2
    ├── input.byte3
    ├── input.byte4
    ├── input.inst_pos_emb
    ├── input.label
    ├── input.op_pos_emb
    └── input.static
```

If you have multiple binaries, you will have to copy the lines of the same files into the training, validation, and test set files. For example, if you have dozens of binaries as the training set, you will copy the lines of each binary's `self/input.label` lines into the training set's `self/input.label`.

### Parameters

For dataset preparation, we filter out internal functions with too large or too small function bodies based on the number of tokens in their function body. For more details, please refer to [this line](https://github.com/pschap/SymLM/blob/cef82e690960871169c4028762e84b3b1e7f02b8/dataset_generation/utils/linux_utils.py#L194).

Moreover, you can set the number of callers and callees considered by `--top_k` of `prepare_dataset.py`. Based on our experience of the SymLM authors, this parameter is bounded by the memory of GPUs. 

### Sample Dataset

We provide a sample dataset for `x64` binaries under the [`dataset_sample`](dataset_sample) directory, which contains training, validation, and test datasets generated by the above steps.

### Dataset Encoding

Dataset encoding is to encode tokens of the dataset generated from binaries in the above steps and generate the binarized files which are more efficient for training and testing.

### Vocabulary Generation

The vocabularies of `input.arch_emb`, `input.byte1`, `input.byte2`, `input.byte3`, `input.byte4`, `input.inst_pos_emb`, `input.op_pos_emb`, and `input.static` are fixed for each architecture. Therefore, we provide them under [`vocabulary`](vocabulary) directory.Note that, for `input.static`, we only cover tokens of {`x64`, `x86`, `arm`, `mips`}.

Since we consider the internal and external functions differently, the vocabularies of them should be generated separately.

To elaborate, we use the sample dataset under [`dataset_sample`](dataset_sample) directory as an example.

For internal functions, generate their vocabulary by:

```bash
python get_vocab_for_binarization.py --src_file dataset_sample/train/self/input.label --output_dir vocabulary/label/
```

For external functions, first merge function names under all external callee directories, and then use the same step to get its vocabulary:

```bash
cat dataset_sample/train/external_callee1/input.label dataset_sample/train/external_callee2/input.label >> vocabulary/external_label/src_file.label
python get_vocab_for_binarization.py --src_file vocabulary/external_label/src_file.label --output_dir vocabulary/external_label/
```

We provide the vocabularies of both internal and external functions under [`vocabulary/label`](vocabulary/label) and [`vocabulary/external_label`](vocabulary/external_label) directory.

### Dataset Binarization

To binarize the dataset, run the `binarize_dataset.py` script. For example, to binarize the sample dataset (under the [`dataset_sample`](dataset_sample) directory) with the above vocabularies, run the following command:

```bash
python binarize_dataset.py --data_src_dir dataset_sample/ --data_bin_dir ../data_bin/ --top_k 2
```

The resulting binarized dataset is under [`../data_bin`](../data_bin) directory.

