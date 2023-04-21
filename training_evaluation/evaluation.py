import argparse
import json
import torch
from transformers import BertTokenizer, BertModel

# Initialize Tokenizer and Model
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
model = BertModel.from_pretrained('bert-base-uncased', output_hidden_states=True)
model.eval()

def parse_args():
    """
    Command-line arguments to the system.
    :return: the provided parsed args bundle
    """

    parser = argparse.ArgumentParser()

    # Evaluation Input
    parser.add_argument('--evaluation-input', type=str, 
                        help='Path to the evaluation input file')
    
    # Word Cluster
    parser.add_argument('--word-cluster', type=str,
                        help='Path to evaluation word cluster')
    
    # Probability Threshold
    parser.add_argument('--prob-threshold', type=float, default=0.3, 
                        help='Probability threshold for selecting the predicted words')
    
    # Similarity threshold for accuracy score
    parser.add_argument('--similarity-threshold', type=float, default=0.9, 
                        help='Similarity threshold for determining semantic similarity between target and predicted function names')
    
    args = parser.parse_args()
    return args

def get_top_prob(prediction, probability, prob_threshold=0.5):
    """
    Returns the predicted function name given the probabilities
    of each word in the vocabulary appearing within the function name.
    A word is included in the predicted function name if the probability
    of that word occurring is greater than or equal to the probability threshold.

    :param prediction: the predicted words in the function name
    :param probability: the probability of each word within the predicted name
    :param prob_threshold: the probability threshold for including functions within the final predicted name
    :return: predicted function name where each word in the predicted name occurs with probability >= prob_threshold
    """

    preds = prediction.split(' ')
    probs = probability.replace('[', '').replace(']', '')
    probs = probs.split(' ')
    res = []
    for i, prob in enumerate(probs):
        prob = float(prob)
        if prob >= prob_threshold:
            res.append(preds[i])
    
    if len(res) == 0:
        res = preds[:1]

    return ' '.join(res)

def split_words(func_name):
    """
    Splits a function name into the individual words
    that make up the function name.

    :param func_name: the function name
    :return: the split function name
    """

    return func_name.lower().strip().split(' ')

def get_correct_prediction_word_cluster(target, prediction, word_cluster, threshold=0.9):
    """
    Calculate the number of true positives, false positives, and false negatives
    for a single function name prediction. The prediction is deemed accurate
    if the vector embeddings of the target and predicted function names meet a specified
    similarity threshold. 

    :param target: the target function name
    :param prediction: the predicted function name
    :param word_cluster: the word cluster
    :param threshold: similarity threshold
    :return: tuple containing number of true positives, false positives, false negatives and 1 if the prediction is accurate; 0 otherwise
    """

    true_positive = 0
    false_positive = 0
    false_negative = 0
    accuracy = 0
    replacement = dict()
    skip = set()

    for j, p in enumerate(prediction):
        if p in target:
            skip.add(j)

    for i, t in enumerate(target):
        for j, p in enumerate(prediction):
            if t != p and j not in replacement and j not in skip:
                if t in word_cluster and p in word_cluster:
                    t_cluster = word_cluster[t]
                    p_cluster = word_cluster[p]
                    t_cluster, p_cluster = set(t_cluster), set(p_cluster)
                    if len(t_cluster.intersection(p_cluster)) > 0:
                        replacement[j] = t

    for k, v in replacement.items():
        prediction[k] = v
    
    if target == prediction:
        true_positive = len(target)
        accuracy = 1
    else:
        target = set(target)
        prediction = set(prediction)

        true_positive += len(target.intersection(prediction))
        false_positive += len(prediction) - true_positive
        false_negative += len(target) - true_positive
        accuracy = is_accurate(target, prediction, threshold)

    return true_positive, false_positive, false_negative, accuracy

def is_accurate(target, prediction, threshold=0.9):
    """
    Determines if the prediction is accurate by comparing the similarity
    between the BERT model vector embedding of the target and predicted
    function names. 

    :param target: the target function name
    :param prediction: the predicted function name
    :param threshold: similarity threshold
    :return: 1 if similarity between vector embeddings is greater than or equal to the threshold; 0 otherwise
    """

    # Calculate accuracy based on semantic similarity between prediction
    # and target
    accuracy = 0
    cos = torch.nn.CosineSimilarity(dim=0, eps=1e-6)
    prediction_str = ' '.join(prediction)
    target_str = ' '.join(target)

    pred_encoded_dict = tokenizer.encode_plus(
                                prediction_str,                 # Sentence to encode
                                add_special_tokens = True,      # Add '[CLS]' and '[SEP]'
                                max_length = len(target_str),   # Pad and truncate all sentences
                                pad_to_max_length = True,       # Pad all token lists with 0s to max length
                                return_attention_mask = True,   # Construction attention masks
                                return_tensors = 'pt'           # Return pytorch tensors
    )

    pred_input_tensor = pred_encoded_dict['input_ids']
    pred_token_tensor = pred_encoded_dict['token_type_ids']
    pred_attention_tensor = pred_encoded_dict['attention_mask']

    target_encoded_dict = tokenizer.encode_plus(
                                target_str,
                                add_special_tokens = True,
                                max_length = len(target_str),
                                pad_to_max_length = True,
                                return_attention_mask = True,
                                return_tensors = 'pt'
    )

    target_input_tensor = target_encoded_dict['input_ids']
    target_token_tensor = target_encoded_dict['token_type_ids']
    target_attention_tensor = target_encoded_dict['attention_mask']

    with torch.no_grad():
        pred_outputs = model(input_ids = pred_input_tensor, token_type_ids = pred_token_tensor, attention_mask = pred_attention_tensor)
        target_outputs = model(input_ids = target_input_tensor, token_type_ids = target_token_tensor, attention_mask = target_attention_tensor)

        pred_hidden = pred_outputs[2]
        pred_embedding = torch.mean(pred_hidden[-2][0], dim = 0)
        target_hidden = target_outputs[2]
        target_embedding = torch.mean(target_hidden[-2][0], dim = 0)

        similarity = cos(pred_embedding, target_embedding)
        if similarity > threshold:
            accuracy = 1

    return accuracy

def calculate_results(true_positive, false_positive, false_negative, correct, total):
    """
    Calculates precision, recall, F1-Score and accuracy.

    :param true_positive: number of true positives
    :param false_positive: number of false positives
    :param false_negative: number of false negatives
    :param correct: number of correct predictions
    :param total: total number of predictions made
    :return: tuple of the form (Precision, Recall, F1, Accuracy)
    """

    if true_positive + false_positive == 0:
        return 0, 0, 0, 0
    
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)
    accuracy = correct / total

    if precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0

    return precision, recall, f1, accuracy

def main():
    """
    Calculate and output evaluation results.
    """

    # Parse arguments
    args = parse_args()
    evaluation_input = args.evaluation_input
    word_cluster_path = args.word_cluster
    prob_threshold = args.prob_threshold
    similarity_threshold = args.similarity_threshold

    with open(word_cluster_path, 'r') as f:
        word_cluster = json.load(f)

    true_positive = 0
    false_positive = 0
    false_negative = 0
    total = 0
    correct = 0
    targets = []
    predictions = []
    
    with open(evaluation_input, 'r') as f:
        for _, line in enumerate(f):
            total += 1
            line = line.strip('\n')
            lines = line.split(',')

            # Generate final predicted function name by using the predicted name
            # and only keep words with a probability greater than or equal to the probability threshold
            lines[1] = get_top_prob(lines[1], lines[2], prob_threshold=prob_threshold)

            # Assert that the prediction is not empty
            assert isinstance(lines[1], str) and len(lines[1]) > 0, "Empty prediction"

            targets.append(lines[0])
            predictions.append(lines[1])
            target = split_words(lines[0])
            prediction = split_words(lines[1])

            tp, fp, fn, acc = get_correct_prediction_word_cluster(target, prediction, word_cluster, threshold=similarity_threshold)
            true_positive += tp
            false_positive += fp
            false_negative += fn
            correct += acc

    precision, recall, f1, accuracy = calculate_results(true_positive, false_positive, false_negative, correct, total)
    print("Probability Threshold = {}, Precision: {}, Recall: {}, F1: {}, Accuracy: {}".format(prob_threshold, precision, recall,
                                                                                               f1, accuracy))

if __name__ == '__main__':
    main()
    