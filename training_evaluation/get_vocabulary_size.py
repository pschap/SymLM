import argparse

def parse_args():
    """
    Command-line arguments to the system.
    :return: the provided parsed args bundle
    """

    parser = argparse.ArgumentParser()

    # Internal Functions
    parser.add_argument('--internal_vocabulary_path', type=str, help='Path to the vocabulary file of internal function name words.')

    # External Functions
    parser.add_argument('--external_vocabulary_path', type=str, help='Path to vocabulary file of external function names.')

    args = parser.parse_args()
    return args

def main():
    """
    Prints the sizes of the vocabulary of internal function name words
    and external function name words.
    """
    
    args = parse_args()
    internal_vocabulary_path = args.internal_vocabulary_path
    external_vocabulary_path = args.external_vocabulary_path

    with open(internal_vocabulary_path, 'r') as f:
        # +1 is to add the <UNK> token for OOV word prediction
        print(f"NUM_CLASSES={len(f.readlines()) + 1}")

    with open(external_vocabulary_path, 'r') as f:
        print(f"NUM_EXTERNAL={len(f.readlines())}")

if __name__ == '__main__':
    main()

