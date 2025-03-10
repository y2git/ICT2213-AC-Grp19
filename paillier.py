import random
import math
from sympy import isprime, nextprime
import time


def timing_decorator(func):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()  # High resolution timer
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"{func.__name__} executed in {end - start:.6f} seconds")
        return result
    return wrapper

def generate_keys(key_size=1024):
    """
    Generate a Paillier key pair
    Returns: ((n, g), (lambda_n, mu))
    where (n, g) is the public key and (lambda_n, mu) is the private key
    """
    # Generate two large prime numbers p and q
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)

    # Compute n = p*q
    n = p * q

    # Compute lambda_n = lcm(p-1, q-1)
    lambda_n = lcm(p - 1, q - 1)

    # Select random g in Z*_n^2
    g = random.randint(1, n ** 2 - 1)

    # Ensure g is in the right set
    while math.gcd(g, n) != 1:
        g = random.randint(1, n ** 2 - 1)

    # Compute mu = (L(g^lambda mod n^2))^(-1) mod n
    # where L(x) = (x-1)/n
    def L(x):
        return (x - 1) // n

    # Calculate g^lambda mod n^2
    g_lambda = pow(g, lambda_n, n ** 2)

    # Calculate L(g^lambda mod n^2)
    l_value = L(g_lambda)

    # Calculate the modular inverse of L(g^lambda mod n^2) mod n
    mu = mod_inverse(l_value, n)

    return ((n, g), (lambda_n, mu))


def encrypt(public_key, m):
    """
    Encrypt a message using Paillier encryption
    public_key: (n, g)
    m: message (integer)
    Returns: ciphertext
    """
    n, g = public_key

    # Ensure message is in the proper range
    if m < 0 or m >= n:
        raise ValueError(f"Message must be in range [0, {n})")

    # Choose a random r in Z*_n
    r = random.randint(1, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    # Compute ciphertext: g^m * r^n mod n^2
    n_squared = n * n
    g_m = pow(g, m, n_squared)
    r_n = pow(r, n, n_squared)
    ciphertext = (g_m * r_n) % n_squared

    return ciphertext


def decrypt(private_key, public_key, ciphertext):
    """
    Decrypt a ciphertext using Paillier decryption
    private_key: (lambda_n, mu)
    public_key: (n, g)
    ciphertext: encrypted message
    Returns: decrypted message
    """
    lambda_n, mu = private_key
    n, g = public_key
    n_squared = n * n

    # Ensure ciphertext is in the proper range
    if ciphertext < 0 or ciphertext >= n_squared:
        raise ValueError(f"Ciphertext must be in range [0, {n_squared})")

    # Compute L(c^lambda mod n^2)
    def L(x):
        return (x - 1) // n

    c_lambda = pow(ciphertext, lambda_n, n_squared)
    message = (L(c_lambda) * mu) % n

    return message


# Homomorphic operations
def add_encrypted(public_key, c1, c2):
    """
    Add two encrypted values homomorphically
    E(m1) * E(m2) = E(m1 + m2)
    """
    n, g = public_key
    n_squared = n * n
    return (c1 * c2) % n_squared


def multiply_constant(public_key, ciphertext, constant):
    n, g = public_key
    n_squared = n * n
    if constant < 0:
        positive_result = pow(ciphertext, abs(constant), n_squared)
        return pow(positive_result, -1, n_squared)  # Modular inverse of positive_result mod n_squared
    else:
        return pow(ciphertext, constant, n_squared)


def subtract_encrypted(public_key, c1, c2):
    n, g = public_key
    n_squared = n * n
    c2_inv = pow(c2, -1, n_squared)  # Modular inverse of c2 mod n_squared
    return (c1 * c2_inv) % n_squared


def generate_prime(bits):
    """Generate a prime number with specified bit length"""
    # Start with a random number of the right bit size
    p = random.getrandbits(bits)
    # Ensure it has the required bit length
    p |= (1 << bits - 1) | 1
    # Find the next prime
    return nextprime(p)


def lcm(a, b):
    """Compute least common multiple"""
    return a * b // math.gcd(a, b)


def mod_inverse(a, m):
    """Compute modular multiplicative inverse a^(-1) mod m"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


# Helper functions for proximity check
def encrypt_location(public_key, x, y):
    """
    Encrypt location coordinates for proximity check
    Returns: (E(x), E(y), E(x^2), E(y^2))
    """
    E_x = encrypt(public_key, x)
    E_y = encrypt(public_key, y)
    E_x_squared = encrypt(public_key, x * x)
    E_y_squared = encrypt(public_key, y * y)

    return (E_x, E_y, E_x_squared, E_y_squared)

def serialize_ciphertext(ciphertext):
    """Convert Paillier ciphertext to string for transmission"""
    return str(ciphertext)


def deserialize_ciphertext(ciphertext_str):
    """Convert string back to Paillier ciphertext"""
    return int(ciphertext_str)


def serialize_encrypted_location(encrypted_loc):
    """Serialize encrypted location tuple for transmission"""
    E_x, E_y, E_x_squared, E_y_squared = encrypted_loc
    return f"{E_x}|{E_y}|{E_x_squared}|{E_y_squared}"


def deserialize_encrypted_location(encrypted_loc_str):
    """Deserialize encrypted location string to tuple"""
    parts = encrypted_loc_str.split('|')
    if len(parts) != 4:
        raise ValueError("Invalid encrypted location format")
    return tuple(int(part) for part in parts)

@timing_decorator
def compute_proximity(public_key, encrypted_loc, my_x, my_y, threshold=2500):
    """
    Compute encrypted proximity result using homomorphic properties

    We need to calculate: E((my_x - x)^2 + (my_y - y)^2 - threshold)

    This should be negative if the squared distance is less than threshold
    """
    print(f"\n==== DEBUG: COMPUTE_PROXIMITY ====")
    print(f"My coordinates: ({my_x}, {my_y})")
    print(f"Threshold: {threshold}")
    print(f"Public key: {str(public_key)[:50]}...")

    E_x, E_y, E_x_squared, E_y_squared = encrypted_loc
    n, g = public_key

    print(f"Extracted encrypted location components")

    # We'll use a more direct approach to calculate the distance
    try:
        # We want to compute: (my_x - x)^2 + (my_y - y)^2
        # This expands to: my_x^2 - 2*my_x*x + x^2 + my_y^2 - 2*my_y*y + y^2

        # 1. Calculate my_x^2 and my_y^2
        my_x_squared = (my_x * my_x)
        my_y_squared = (my_y * my_y)
        print(f"My coordinates squared: ({my_x_squared}, {my_y_squared})")

        # We want to compute E(my_x^2 + my_y^2)
        plaintext_sum = my_x_squared + my_y_squared
        print(f"Sum of my squared coordinates: {plaintext_sum}")
        E_my_squared_sum = encrypt(public_key, plaintext_sum)

        # 2. Calculate E(-2*my_x*x) and E(-2*my_y*y)
        # For multiplying by negative numbers, we need special handling
        mult_x = -2 * my_x
        mult_y = -2 * my_y
        print(f"Multipliers (modulo n): x={mult_x}, y={mult_y}")

        # 3. Apply the multipliers to the encrypted x and y
        E_term_x = multiply_constant(public_key, E_x, mult_x)
        E_term_y = multiply_constant(public_key, E_y, mult_y)

        # 4. Combine all terms: E(my_x^2 + my_y^2) + E(-2*my_x*x) + E(-2*my_y*y) + E(x^2) + E(y^2)
        print(f"Building distance calculation...")

        # Start with E(my_x^2 + my_y^2)
        E_dist_squared = E_my_squared_sum
        print(f"  + E(my_x^2 + my_y^2)")

        # Add E(-2*my_x*x)
        E_dist_squared = add_encrypted(public_key, E_dist_squared, E_term_x)
        print(f"  + E(-2*my_x*x)")

        # Add E(-2*my_y*y)
        E_dist_squared = add_encrypted(public_key, E_dist_squared, E_term_y)
        print(f"  + E(-2*my_y*y)")

        # Add E(x^2)
        E_dist_squared = add_encrypted(public_key, E_dist_squared, E_x_squared)
        print(f"  + E(x^2)")

        # Add E(y^2)
        E_dist_squared = add_encrypted(public_key, E_dist_squared, E_y_squared)
        print(f"  + E(y^2)")

        print(f"Completed calculation of E(distance^2)")

        # IMPORTANT: Encrypt the threshold with the same public key
        E_threshold = encrypt(public_key, threshold)

        # Subtract threshold from the squared distance
        E_dist_squared_minus_threshold = subtract_encrypted(
            public_key,
            E_dist_squared,
            E_threshold
        )

        print(f"Successfully computed E(distance^2 - threshold)")
        print(f"==== END DEBUG: COMPUTE_PROXIMITY ====\n")

        return E_dist_squared_minus_threshold

    except Exception as e:
        print(f"ERROR in compute_proximity: {e}")
        import traceback
        traceback.print_exc()
        raise