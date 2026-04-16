import socket
import threading
import hashlib
from rsa import generate_keypair, key_to_string, string_to_key, encrypt_to_string, decrypt_from_string


def compute_hash(message):
    '''Returns SHA-256 hash of a message string.'''
    return hashlib.sha256(message.encode()).hexdigest()


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_pub_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        print("[server]: generating RSA keys...")
        self.pub_key, self.priv_key = generate_keypair(bits=512)
        print("[server]: ready, waiting for connections...")

        while True:
            c, addr = self.s.accept()
            threading.Thread(target=self.handle_new_client, args=(c,), daemon=True).start()

    def handle_new_client(self, c):
        username = c.recv(1024).decode()
        print(f"{username} tries to connect")
        c.send(key_to_string(self.pub_key).encode())
        client_pub_key = string_to_key(c.recv(4096).decode())
        self.clients.append(c)
        self.username_lookup[c] = username
        self.client_pub_keys[c] = client_pub_key
        self.broadcast(f"new person has joined: {username}")
        threading.Thread(target=self.handle_client, args=(c,), daemon=True).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            try:
                # encrypt message using each client's public key
                encrypted = encrypt_to_string(msg, self.client_pub_keys[client])
                msg_hash = compute_hash(msg)
                client.send(f"{msg_hash}|{encrypted}".encode())
            except Exception as e:
                print(f"[server]: broadcast error: {e}")

    def handle_client(self, c: socket):
        while True:
            try:
                data = c.recv(65536).decode()

                # unpack hash and encrypted message
                received_hash, encrypted_msg = data.split("|", 1)

                # decrypt with server's private key
                decrypted_msg = decrypt_from_string(encrypted_msg, self.priv_key)

                if compute_hash(decrypted_msg) != received_hash:
                    print("[server]: WARNING - message integrity check failed!")
                    continue

                username = self.username_lookup[c]
                full_message = f"{username}: {decrypted_msg}"
                print(full_message)

                # forward to all other clients
                for client in self.clients:
                    if client != c:
                        encrypted = encrypt_to_string(full_message, self.client_pub_keys[client])
                        msg_hash = compute_hash(full_message)
                        client.send(f"{msg_hash}|{encrypted}".encode())

            except Exception as e:
                username = self.username_lookup.get(c, "unknown")
                print(f"[server]: {username} disconnected")
                self.clients.remove(c)
                c.close()
                break


if __name__ == "__main__":
    s = Server(9001)
    s.start()
