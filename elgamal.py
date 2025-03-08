import random
from sympy import nextprime

def generate_keys(key_bits=128):
    p = nextprime(2**key_bits)
    g = random.randint(2, p-2)
    x = random.randint(1, p-2)
    h = pow(g, x, p)
    return (p, g, h), (p, x)

def encrypt(public_key, plaintext):
    p, g, h = public_key
    y = random.randint(1, p-2)
    c1 = pow(g, y, p)
    c2 = (pow(h, y, p) * plaintext) % p
    return c1, c2

def decrypt(private_key, c1, c2):
    p, x = private_key
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p

# Homomorphic operations for proximity checking
# Updated homomorphic operations
def homomorphic_add(c1, c2, p):
    """Add two ciphertexts homomorphically"""
    return (c1[0] * c2[0] % p, c1[1] * c2[1] % p)

def homomorphic_subtract(c1, c2, p):
    """Subtract ciphertexts homomorphically"""
    # Compute multiplicative inverse of c2
    c2_inv = (pow(c2[0], p-2, p), pow(c2[1], p-2, p))  # Using Fermat's little theorem
    return (c1[0] * c2_inv[0] % p, c1[1] * c2_inv[1] % p)

def homomorphic_multiply(c, scalar, p):
    """Multiply ciphertext by scalar homomorphically"""
    return (pow(c[0], scalar, p), pow(c[1], scalar, p))

def homomorphic_compare(dist_sq, enc_threshold, p, private_key):
    """Compare encrypted distances"""
    decrypted_dist = decrypt(private_key, dist_sq[0], dist_sq[1])
    decrypted_thresh = decrypt(private_key, enc_threshold[0], enc_threshold[1])
    return decrypted_dist <= decrypted_thresh