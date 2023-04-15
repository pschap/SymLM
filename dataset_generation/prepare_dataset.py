import argparse
import json

from utils.dataset_utils import *

def parse_args():
    """
    Command-line arguments to the system.
    :return: the provided parsed args bundle
    """

    parser = argparse.ArgumentParser(prog='prepare_dataset.py', description='Output dataset representing ground truth function names in binaries')

    # Dataset Output Directory
    parser.add_argument('--output_dir', type=str, help='directory where ground truth dataset is output')

    # Input Binary
    parser.add_argument('--input_binary', type=str, help='name and path of input binary')

    # ICFG
    parser.add_argument('--icfg_dir', type=str, default='icfg', help='directory in which the ICFG is located')

    # Arguments for Windows Binaries
    parser.add_argument('--is_portable_executable', type=bool, default=False, help='true if the binary is a windows (Portable Executable) binary; false otherwise')
    parser.add_argument('--symbol_path', type=str, default=str(), nargs='?', const='', help='path to symbol path for input binary')

    # Architecture
    parser.add_argument('--arch', type=str, help='architecture of binary; x86, x64, mips, and arm are currently supported')

    # Top Popular Callers
    parser.add_argument('--top_k', type=int, default=2, help='number of top popular callers (callees) to be selected')

    args = parser.parse_args()
    return args

def main():
    """
    Creates ground truth dataset for a given binary. 
    """
    args = parse_args()

    output_dir = args.output_dir
    input_binary = args.input_binary
    icfg_dir = args.icfg_dir
    is_portable_executable = args.is_portable_executable
    symbol_path = args.symbol_path
    arch = args.arch
    top_k = args.top_k

    # Create Dataset Output Directories
    create_dataset_dirs(output_dir, input_binary, top_k)
    
    # Check if the calling context metadata (ICFG) exists
    if not os.path.exists(icfg_dir):
        print('[-]', f"ICFG file {icfg_dir} does not exist")
        return

    # Load calling context metadata (ICFG)
    with open(icfg_dir, 'r') as f:
        print('[*]', f"Loading ICFG File: {icfg_dir}")
        calling_context_dict = json.load(f)

    # Select top popular callers and callees
    target_context_dict = rank_calling_context(calling_context_dict)

    # Create dataset output files
    files = open_dataset_files(output_dir, input_binary, top_k)

    # Get Capstone Object
    cs_obj = get_capstone_obj(arch)
    if cs_obj is None:
        print('[-]', f'Unrecognized architecture: {arch}. Exiting...')
        return
    
    # Generate Micro-Traces for the Input Binary
    if is_portable_executable:
        from utils.windows_utils import create_micro_trace_dict
        micro_trace_dict = create_micro_trace_dict(input_binary, symbol_path, calling_context_dict, arch, cs_obj)
    else:
        from utils.linux_utils import create_micro_trace_dict
        micro_trace_dict = create_micro_trace_dict(input_binary, calling_context_dict, arch, cs_obj)

    # Write output sequences and close files
    write_output_sequences(micro_trace_dict, arch, target_context_dict, files, top_k)
    close_dataset_files(files, top_k)
    assert_file_validity(output_dir, input_binary)

    print('[*]', f'Dataset for {input_binary} is generated in: {output_dir}')


if __name__ == '__main__':
    main()
