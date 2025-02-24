# this is just a refernce for our project... delete after
# https://www.kaggle.com/code/jamestashvik/elgamal-testing
from Crypto.Util.number import getPrime, inverse
import random

# Step 1: Key Generation for ElGamal
def generate_keys(bit_length=256):
    p = getPrime(bit_length)  # Large prime number
    g = random.randint(2, p - 1)  # Generator g
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key h = g^x mod p
    return (p, g, h, x)  # Public key (p, g, h), private key x

# Step 2: Encryption using ElGamal
def encrypt(public_key, message):
    p, g, h = public_key
    r = random.randint(1, p - 2)  # Ephemeral key
    c1 = pow(g, r, p)            # c1 = g^r mod p
    c2 = (message * pow(h, r, p)) % p  # c2 = m * h^r mod p
    return (c1, c2)

# Step 3: Decryption using ElGamal
def decrypt(private_key, public_key, ciphertext):
    p, _, _ = public_key
    c1, c2 = ciphertext
    x = private_key
    s = pow(c1, x, p)      # Shared secret s = c1^x mod p
    s_inv = inverse(s, p)  # Modular inverse of s
    message = (c2 * s_inv) % p  # m = c2 * s^-1 mod p
    return message

# Step 4: Homomorphic "difference" function (but actually computing a ratio)
# This produces an encryption of (m1 / m2) mod p
def homomorphic_ratio(ciphertext1, ciphertext2, p):
    c1_ratio = (ciphertext1[0] * inverse(ciphertext2[0], p)) % p
    c2_ratio = (ciphertext1[1] * inverse(ciphertext2[1], p)) % p
    return (c1_ratio, c2_ratio)

def main():
    # Step 1: Key generation
    bit_length = 256
    p, g, h, x = generate_keys(bit_length)
    public_key = (p, g, h)
    private_key = x

    print(f"Prime p: {p}")
    print(f"Generator g: {g}")
    print(f"Public key h: {h}")
    print(f"Private key x: {x}")

    # Step 2: Each client's location is an integer from 1..10000
    location_A = 3456  # e.g., 3456
    location_B = 3456  # e.g., 3456

    print(f"Location A: {location_A}")
    print(f"Location B: {location_B}")

    # Step 3: Encrypt both locations
    ciphertext_A = encrypt(public_key, location_A)
    ciphertext_B = encrypt(public_key, location_B)

    print("Encrypted Location A:", ciphertext_A)
    print("Encrypted Location B:", ciphertext_B)

    # Step 4: Compute the encryption of the ratio (locationA / locationB)
    ciphertext_ratio = homomorphic_ratio(ciphertext_A, ciphertext_B, p)
    print("Ciphertext Ratio:", ciphertext_ratio)

    # Step 5: Decrypt the ratio
    decrypted_ratio = decrypt(private_key, public_key, ciphertext_ratio)
    print("Decrypted Ratio:", decrypted_ratio)

    # Step 6: Convert ratio to a "difference-like" value:
    # diff = ratio - 1 (mod p). If ratio == 1 => diff == 0 => same cell.
    decrypted_diff = (decrypted_ratio - 1) % p
    print("Decrypted \"Difference\":", decrypted_diff)

    # Step 7: Check if diff == 0 => same cell
    if decrypted_diff == 0:
        print("Clients A and B are in the SAME cell.")
    else:
        print("Clients A and B are in DIFFERENT cells.")

if __name__ == "__main__":
    main()