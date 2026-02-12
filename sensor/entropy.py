import math
import collections

def calculate_entropy(filepath):
    """
    Reads a file and calculates its Shannon Entropy.
    Returns a float between 0.0 (Order) and 8.0 (Random Chaos).
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        if not data:
            return 0.0

        frequency = collections.Counter(data)
        file_len = len(data)
        
        entropy = 0.0
        for count in frequency.values():
            p_x = count / file_len
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
                
        return entropy
    except:
        return 0.0