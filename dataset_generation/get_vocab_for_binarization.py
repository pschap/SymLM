import os
import shutil
import subprocess
import argparse

def parse_args():
    """
    Command-line arguments to the system.
    :return: the provided parsed args bundle
    """

    parser = argparse.ArgumentParser(prog="get_vocab_for_binarization.py", description="Output ground truth")

    # Label File
    parser.add_argument('--src_file', type=str, help='file where function names are')

    # Vocabulary Output Directory
    parser.add_argument('--output_dir', type=str, help='directory where the generated vocabulary will be stored')

    args = parser.parse_args()
    return args

def main():
    """
    Generate vocabulary for a dataset.
    """

    args = parse_args()
    src_file = args.src_file
    output_dir = args.output_dir

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    subprocess.run([
        'fairseq-preprocess', '--only-source',
        '--trainpref', src_file,
        '--destdir', output_dir,
        '--workers', '40'
    ])

    print("[*] Generated vocabulary at {}".format(os.path.join(output_dir, 'dict.txt')))

if __name__ == '__main__':
    main()
