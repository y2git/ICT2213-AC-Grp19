

def string_to_int(message):
    """
    Convert a UTF-8 string to an integer.
    """
    return int.from_bytes(message.encode('utf-8'), 'big')

def int_to_string(number):
    """
    Convert an integer back to a UTF-8 string.
    """
    try:
        num_bytes = (number.bit_length() + 7) // 8
        return number.to_bytes(num_bytes, 'big').decode('utf-8')
    except UnicodeDecodeError as e:
        print(f"Error decoding bytes to UTF-8: {e}")
        # You could try a different encoding or just return a placeholder
        return f"[Error: Could not decode message. Raw value: {number}]"

def serialize_ciphertext(ciphertext):
    """
    Serialize a ciphertext (tuple of integers) into a string.
    Here we join the two components with a delimiter.
    """
    c1, c2 = ciphertext
    return f"{c1}|{c2}"

def deserialize_ciphertext(serialized):
    """
    Deserialize a ciphertext string back into a tuple of integers.
    """
    c1_str, c2_str = serialized.split('|')
    return (int(c1_str), int(c2_str))
