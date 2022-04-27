import random


def random_binary_string(str_len):
    """
        function to create a random binary string with varying length for XOR encoding
        args:
            str_len: length of the desired binary string
        return:
            a random binary string with length = str_len
    """
    s = ""
    for _ in range(str_len):
        s += str(random.randint(0, 1))
    return s