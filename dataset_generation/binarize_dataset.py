import subprocess
import argparse

from multiprocessing import Pool
from itertools import product

fields = ['static', 'inst_pos_emb', 'op_pos_emb', 'arch_emb', 'byte1', 'byte2', 'byte3', 'byte4']
targets = ['self']

def parse_args():
    """
    Command-line arguments to the system.
    :return: the provided parsed args bundle
    """

    parser = argparse.ArgumentParser(description='Output ground truth')

    # Dataset Directory
    parser.add_argument('--data_src_dir', type=str, help='directory where the dataset to be binarized is stored')

    # Binarized Dataset Output Directory
    parser.add_argument('--data_bin_dir', type=str, help='directory where the binarized result is to be stored')

    # Top Popular Callers/Callees
    parser.add_argument('--top_k', type=int, help='number of top popular callers/callees to be selected')

    args = parser.parse_args()
    return args

def run(data_src_dir, data_bin_dir, target, field):
    """
    Uses the fairseq preprocess script to perform dataset binarization for a 
    given target and field.

    :param data_src_dir: directory where the dataset to be binarized is stored
    :param data_bin_dir: directory where the binarized dataset is to be stored
    :param target: one of the top-k callers/callees
    :param field: dataset field (arch_emb, byte1, byte2, byte3, byte4, inst_pos_emb, op_pos_emb, static)
    """

    subprocess.run([
        'fairseq-preprocess', '--only-source',
        '--srcdict', f'vocabulary/{field}/dict.txt',
        '--trainpref', f'{data_src_dir}/train/{target}/input.{field}',
        '--validpref', f'{data_src_dir}/valid/{target}/input.{field}',
        '--testpref', f'{data_src_dir}/test/{target}/input.{field}',
        '--destdir', f'{data_bin_dir}/{target}/{field}',
        '--workers', '40'
    ])

def main():
    """
    Perform dataset binarization.
    """
    
    # Parse Arguments
    args = parse_args()
    data_src_dir = args.data_src_dir
    data_bin_dir = args.data_bin_dir
    top_k = args.top_k

    if data_src_dir[-1] == '/':
        data_src_dir = data_src_dir[:-1]
    if data_bin_dir[-1] == '/':
        data_bin_dir = data_bin_dir[:-1]

    for i in range(top_k):
        targets.append(f"caller{i+1}")
        targets.append(f"internal_callee{i+1}")

    # Binarize Fields
    with Pool() as pool:
        pool.starmap(run, product([data_src_dir], [data_bin_dir], targets, fields))

    # Binarize Labels
    for target in ['self'] + [f'external_callee{i+1}' for i in range(top_k)]:
        if target =='self':
            src_dict = 'vocabulary/label/dict.txt'
        else:
            src_dict = 'vocabulary/external_label/dict.txt'

        subprocess.run([
            'fairseq-preprocess', '--only-source',
            '--srcdict', src_dict,
            '--trainpref', f'{data_src_dir}/train/{target}/input.label',
            '--validpref', f'{data_src_dir}/valid/{target}/input.label',
            '--testpref', f'{data_src_dir}/test/{target}/input.label',
            '--destdir', f'{data_bin_dir}/{target}/label',
            '--workers', '40'
        ])

    subprocess.run(['cp', '-r', f'vocabulary/cover', f'{data_bin_dir}/self/'])

    print("[*] Binarized dataset under {}".format(data_bin_dir))

if __name__ == '__main__':
    main()
