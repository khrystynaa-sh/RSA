import socket
import threading
import hashlib
from rsa import generate_keypair, key_to_string, string_to_key, encrypt_to_string, decrypt_from_string


def compute_hash(message):
    '''Returns SHA-256 hash of a message string'''
    return hashlib.sha256(message.encode()).hexdigest()


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        print("[client]: generating RSA keys...")
        self.pub_key, self.priv_key = generate_keypair(bits=512)

        # receive server's public key
        self.server_pub_key = string_to_key(self.s.recv(4096).decode())

        # send public key to the server
        self.s.send(key_to_string(self.pub_key).encode())

        print("[client]: connected! You can start chatting.\n")

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            try:
                data = self.s.recv(65536).decode()

                # unpack hash and encrypted message
                received_hash, encrypted_msg = data.split("|", 1)

                # decrypt with our private key
                decrypted_msg = decrypt_from_string(encrypted_msg, self.priv_key)

                if compute_hash(decrypted_msg) != received_hash:
                    print("[client]: WARNING - message integrity check failed!")
                    continue

                print(decrypted_msg)

            except Exception as e:
                print("[client]: disconnected")
                break

    def write_handler(self):
        while True:
            message = input()

            # compute hash of original message
            msg_hash = compute_hash(message)

            # encrypt message with server's public key
            encrypted = encrypt_to_string(message, self.server_pub_key)

            self.s.send(f"{msg_hash}|{encrypted}".encode())


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
