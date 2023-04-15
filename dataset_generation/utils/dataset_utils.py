import os
import re
import nltk
import glob
import sentencepiece as spm

from .params import *
from collections import Counter
from capstone import *
from nltk.stem.wordnet import WordNetLemmatizer
from nltk.corpus import wordnet

sp = spm.SentencePieceProcessor()
sp.load('segmentation_model/segmentation.model')
lem = WordNetLemmatizer()

try:
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('averaged_perceptron_tagger')

try:
    nltk.data.find('corpora/wordnet.zip/wordnet/')
except LookupError:
    nltk.download('wordnet')

try:
    nltk.data.find('corpora/omw-1.4.zip/omw-1.4/')
except LookupError:
    nltk.download('omw-1.4')

def create_dataset_dirs(output_dir, input_binary, top_k = 2):
    """
    Creates output directories for dataset of ground truth binaries.
    If top_k = 2, then the generated directories are of the following structure:

    output_dir/input_binary
    ├── caller1 
    ├── caller2
    ├── external_callee1
    ├── external_callee2
    ├── internal_callee1
    ├── internal_callee2
    ├── self

    :param output_dir: the directory for which to store all the dataset information
    :param input_binary: the name of the binary for which to create the dataset
    :param top_k: number of top popular callers/callees to be selected
    """

    # Check if output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create top-level directory for output
    binary_output_dir = os.path.join(output_dir, input_binary)
    if not os.path.exists(binary_output_dir):
        print('[*]', f"Creating output folder for binary: {binary_output_dir}")
        os.makedirs(binary_output_dir)

    # Create output directories
    for i in range(top_k):
        # Directory Names
        self_dir = os.path.join(binary_output_dir, 'self')
        caller_dir = os.path.join(binary_output_dir, f'caller{i+1}')
        external_callee_dir = os.path.join(binary_output_dir, f'external_callee{i+1}')
        internal_callee_dir = os.path.join(binary_output_dir, f'internal_callee{i+1}')

        # Create Directories
        if not os.path.exists(self_dir):
            os.makedirs(self_dir)

        if not os.path.exists(caller_dir):
            os.makedirs(caller_dir)

        if not os.path.exists(external_callee_dir):
            os.makedirs(external_callee_dir)

        if not os.path.exists(internal_callee_dir):
            os.makedirs(internal_callee_dir)

def open_dataset_files(output_dir, input_binary, top_k = 2):
    """
    Creates and opens streams to ground-truth dataset files
    so that they can be written to later.

    :param output_dir: the directory for which to store all the dataset information
    :param input_binary: the name of the binary for which to create the dataset
    :param top_k: number of top popular callers/callees to be selected
    """

    # Check if output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Dataset output directory
    binary_output_dir = os.path.join(output_dir, input_binary)

    files = {}

    # Self
    files["self"] = {field: open(os.path.join(binary_output_dir, 'self', f'input.{field}'), 'w') for field in params.fields}

    # Callers
    files["callers"] = []
    for i in range(top_k):
        caller_file = {field: open(os.path.join(binary_output_dir, f'caller{i+1}', f'input.{field}'), 'w') for field in params.context_fields}
        files["callers"].append(caller_file)

    # Internal Callees
    files["internal_callees"] = []
    for i in range(top_k):
        internal_callee_file = {field: open(os.path.join(binary_output_dir, f'internal_callee{i+1}', f'input.{field}'), 'w') for field in params.context_fields}
        files["internal_callees"].append(internal_callee_file)

    # External Callees
    files["external_callees"] = []
    for i in range(top_k):
        external_callee_file = open(os.path.join(binary_output_dir, f'external_callee{i+1}', f'input.label'), 'w')
        files["external_callees"].append(external_callee_file)

    return files


def close_dataset_files(files, top_k = 2):
    """
    Closes streams to ground-truth dataset files.

    :param files: dictionary containing maps from dataset directories to ground truth dataset file objects
    :param top_k: number of top popular callers/callees to be selected
    """

    # Close All Files
    for field in params.fields:
        files['self'][field].close()

    for i in range(top_k):
        for field in params.context_fields:
            files["callers"][i][field].close()
            files["internal_callees"][i][field].close()

        files["external_callees"][i].close()


def rank_elements(target_list):
    """
    Sorts the unique elements of the target list in order of how often they appear
    within the list.

    :param target_list: the target list
    :return: the sorted elements of the target list
    """

    counts = Counter(target_list)
    res = counts.most_common()
    
    return [x[0] for x in res]

def rank_calling_context(calling_context_dict):
    """
    For each function, rank callee and caller functions based on their frequency.

    :param calling_context_dict: calling context dictionary (ICFG) of a binary
    :return: calling context dictionary with callers and callees ordered based on their frequency
    """

    res = {}
    for func_name, calling_context in calling_context_dict.items():
        callers = calling_context['caller']
        callees = calling_context['callee']

        # Rank the elements based on their frequency
        callers = rank_elements(callers)
        callees = rank_elements(callees)

        res[func_name] = {'caller': callers, 'callee': callees}

    return res

def get_capstone_obj(arch):
    """
    Initializes and returns Python class for Capstone given the hardware architecture.

    :param arch: the hardware architecture
    :return: Python class for Capstone initialized given the provided hardware architecture
    """

    if arch == "arm":
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == "x64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "mips":
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    else:
        md = None

    return md

def tokenize(s):
    """
    Performs instruction tokenizing needed in order to generate micro-trace sequences.

    :param s: the string to tokenize
    :return: list of tokens from s
    """

    s = s.replace(',', ' , ')
    s = s.replace('[', ' [ ')
    s = s.replace(']', ' ] ')
    s = s.replace(':', ' : ')
    s = s.replace('*', ' * ')
    s = s.replace('(', ' ( ')
    s = s.replace(')', ' ) ')
    s = s.replace('{', ' { ')
    s = s.replace('}', ' } ')
    s = s.replace('#', '')
    s = s.replace('$', '')
    s = s.replace('!', ' ! ')

    s = re.sub(r'-(0[xX][0-9a-fA-F]+)', r'- \1', s)
    s = re.sub(r'-([0-9a-fA-F]+)', r'- \1', s)

    return s.split()

def hex2seq(s, b_len=8):
    """
    Takes the string representation of a hexadecimal digit and outputs
    a sequence of the bytes contained within the hexadecimal digit.

    :param s: the string representation of the hexadecimal digit
    :param b_len: number of digits in the hexadecimal digit
    :return: list containing each byte of the hexadecimal digit
    """

    hex_num = s.replace('0x', '')

    # Handle Cases where the digit contains more than the desired number of bytes
    # by taking the lower b_len digits
    if len(hex_num) > b_len:
        hex_num = hex_num[-b_len:]

    hex_num = '0' * (b_len - len(hex_num)) + hex_num

    # Get each pair of two digits; each pair corresponds to one bytes
    byte_seq = [hex_num[i:i+2] for i in range(len(hex_num) - 2)]

    return byte_seq

def get_pos(treebank_tag):
    """
    Gets the part-of-speech of a treebank tag.

    :param treebank_tag: the treebank tag
    :return: the part-of-speech of the treebank tag
    """

    if treebank_tag.startswith('J'):
        return wordnet.ADJ
    elif treebank_tag.startswith('V'):
        return wordnet.VERB
    elif treebank_tag.startswith('N'):
        return wordnet.NOUN
    elif treebank_tag.startswith('R'):
        return wordnet.ADV
    else:
        return None # For easy if-statement
    
def func_name_segmentation(word):
    """
    Segment concatenated words into individual words.

    :param word: the word to segment
    :return: the word segmented into individual words
    """

    res = sp.encode_as_pieces(word)
    res[0] = res[0][1:]
    return res

def func_name_preprocessing(func_name):
    """
    Performs preprocessing on a function name by:
        1.) tokenizing whole function name into words
        2.) removing digits
        3.) segmenting concatenated words
        4.) lemmatizing words

    :param func_name: the function name for which to perform preprocessing
    :return: preprocessed function name
    """

    # Split whole function name into words and remove digits
    func_name = func_name.replace('_', ' ')
    tmp = ''
    for c in func_name:
        # Filter out numbers and other special characters, e.g. '_' and digits
        if not c.isalpha(): 
            tmp = tmp + ' '
        elif c.isupper():
            tmp = tmp + ' ' + c
        else:
            tmp = tmp + c

    tmp = tmp.strip()
    tmp = tmp.split(' ')

    res = []
    i = 0
    while i < len(tmp):
        cap = ''
        t = tmp[i]

        # Handle series of capital letters: e.g., SHA, MD
        while i < len(tmp) and len(tmp[i]) == 1:
            cap = cap + tmp[i]
            i += 1
        if len(cap) == 0:
            res.append(t)
            i += 1
        else:
            res.append(cap)

        # Lemmatize words
        words = []
        for word in res:
            if not isinstance(word, str) or word == '':
                continue
            words.append(word)

        tokens = nltk.pos_tag(words)
        res = []
        for word, tag in tokens:
            wntag = get_pos(tag)
            # Do not supply tag in case of None
            if wntag is None:
                word = lem.lemmatize(word)
            else:
                word = lem.lemmatize(word, pos=wntag)
            res.append(word)

        # Segment Concatenated Words
        final_words = []
        for word in res:
            if not isinstance(word, str) or word == '':
                continue
            splitted = func_name_segmentation(word)
            for w in splitted:
                if not isinstance(w, str) or w == '':
                    continue
                final_words.append(w)

        if len(final_words) == 0:
            return None
        
        resulting_name = ' '.join(final_words)
        return resulting_name.lower()

def write_output_sequences(micro_trace_dict, arch, target_context_dict, files, top_k = 2):
    """
    Writes function micro-traces to files in ground-truth dataset. 

    :param micro_trace_dict: dictionary containing micro-trace sequences as defined in the TREX paper
    :param arch: the hardware architecture
    :param target_context_dict: calling context dictionary with callers and callees ordered based on their frequency
    :param files: dictionary containing maps from dataset directories to ground truth dataset file objects
    :param top_k: number of top popular callers/callees to be selected
    """

    target_funcs = list(micro_trace_dict.keys())
    for func_name in target_funcs:
        # Step 1: Write function instruction sequence to file
        output_sequences = micro_trace_dict[func_name]
        for field in params.fields:
            files["self"][field].write(output_sequences[field] + '\n')

        callers = target_context_dict[func_name]['caller']
        callees = target_context_dict[func_name]['callee']

        # Step 2: Get Caller Sequences and write them into file
        useful_caller_count = 0
        caller_output_sequences = []
        for caller in callers:
            if caller in micro_trace_dict:
                useful_caller_count += 1
                caller_output_sequences.append(micro_trace_dict[caller])
            if useful_caller_count >= top_k:
                break

        # If there is not enough useful caller information, then use dummy sequeences 
        while useful_caller_count < top_k:
            useful_caller_count += 1
            caller_output_sequences.append(params.dummy_sequence[arch])

        # Write Caller Sequences into Files
        for i, output_sequence in enumerate(caller_output_sequences):
            for field in params.context_fields:
                files["callers"][i][field].write(output_sequence[field] + '\n')

        # Step 3: Get Callee Sequences and write them into file
        useful_internal_callee_count = 0
        useful_external_callee_count = 0
        callee_output_sequences = []
        callee_external_labels = []
        for callee in callees:
            if callee in micro_trace_dict:
                if useful_internal_callee_count < top_k:
                    useful_internal_callee_count += 1
                    callee_output_sequences.append(micro_trace_dict[callee])
            elif "EXTERNAL" in callee and "::" in callee:
                if useful_external_callee_count < top_k:
                    try:
                        external_callee_name = callee.split("::")[1]
                    except:
                        external_callee_name = '##'

                    useful_external_callee_count += 1
                    callee_external_labels.append(external_callee_name)

        # If there is not enough useful callees, then use dummy sequences
        while useful_internal_callee_count < top_k:
            useful_internal_callee_count += 1
            callee_output_sequences.append(params.dummy_sequence[arch])

        while useful_external_callee_count < top_k:
            useful_external_callee_count += 1
            callee_external_labels.append('##')

        # Write callee sequences into files
        for i, output_sequence in enumerate(callee_output_sequences):
            for field in params.context_fields:
                files["internal_callees"][i][field].write(output_sequence[field] + '\n')

        for i, label in enumerate(callee_external_labels):
            files["external_callees"][i].write(label + '\n')

def get_num_lines(file):
    """
    Gets the number of lines in a file.

    :param file: the file
    :return: the number of lines
    """

    with open(file) as f:
        return sum(1 for _ in f)
    
def assert_file_validity(output_dir, input_binary):
    """
    Asserts that each file in the output ground-truth dataset
    is valid by checking that each file contains the same number of lines.

    :param output_dir: the directory for which to store all the dataset information
    :param input_binary: the name of the binary for which to create the dataset
    """

    # Dataset output directory
    binary_output_dir = os.path.join(output_dir, input_binary)

    # Assert that all files have the same number of lines
    num_lines = get_num_lines(os.path.join(binary_output_dir, 'self', 'input.label'))
    dirs = glob.glob(os.path.join(binary_output_dir, '*'))

    for dir in dirs:
        files = glob.glob(os.path.join(dir, '*'))
        for file in files:
            current_num_lines = get_num_lines(file)
            assert current_num_lines == num_lines, f"Number of lines in files are not the same: \n\t {file}: {current_num_lines} \n\t {os.path.join(binary_output_dir, 'self', 'input.label')}: {num_lines}"