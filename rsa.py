import random


def is_prime(n):
    '''Checks if n is prime using Miller-Rabin test'''
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(20):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    '''Generates a random prime number of given bit length'''
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def extended_gcd(a, b):
    '''Extended Euclidean Algorithm — finds x such that a*x ≡ 1 (mod b)'''
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def mod_inverse(e, phi):
    '''Computes modular inverse: find d such that e*d ≡ 1 (mod phi)'''
    _, x, _ = extended_gcd(e, phi)
    return x % phi


def generate_keypair(bits=512):
    '''
    Generates RSA public and private keys
    Returns: public_key (e, n), private_key (d, n)
    '''
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    d = mod_inverse(e, phi)

    return (e, n), (d, n)


def rsa_encrypt(message_int, public_key):
    '''Encrypts a single integer: c = m^e mod n'''
    e, n = public_key
    return pow(message_int, e, n)


def rsa_decrypt(ciphertext_int, private_key):
    '''Decrypts a single integer: m = c^d mod n'''
    d, n = private_key
    return pow(ciphertext_int, d, n)


def encrypt_message(text, public_key):
    '''
    Encrypts a text message with RSA
    Converts each character to its ASCII number, encrypts it, returns a list of ints
    '''
    return [rsa_encrypt(ord(char), public_key) for char in text]


def decrypt_message(encrypted_list, private_key):
    '''Decrypts a list of encrypted integers back to a text message'''
    return "".join(chr(rsa_decrypt(c, private_key)) for c in encrypted_list)


def key_to_string(key):
    '''Converts a key tuple (e/d, n) to a string for sending over socket'''
    return f"{key[0]}:{key[1]}"


def string_to_key(key_str):
    '''Converts a string back to a key tuple'''
    e, n = key_str.split(":")
    return int(e), int(n)


def encrypt_to_string(text, public_key):
    '''Encrypts text and return it as a comma-separated string of numbers'''
    encrypted = encrypt_message(text, public_key)
    return ",".join(str(n) for n in encrypted)


def decrypt_from_string(encrypted_str, private_key):
    '''Decrypts a comma-separated string of numbers back to text'''
    encrypted_list = [int(n) for n in encrypted_str.split(",")]
    return decrypt_message(encrypted_list, private_key)
