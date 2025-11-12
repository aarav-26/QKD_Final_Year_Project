import socket
import threading
import pickle
import random
import os
import json
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256

# QKD modules
from quantum_key_distribution.bb84 import QKDProtocol
from quantum_key_distribution.entanglement_qkd import EntanglementQKD
from quantum_key_distribution.brahmagupta import brahmagupta_key_composition
from quantum_key_distribution.ramanujan import ramanujan_inspired_kdf, bits_to_bytes

HOST = '0.0.0.0'
PORT = 65432
KEY_LENGTH = 128
QBER_SAMPLE_SIZE = 32
QBER_THRESHOLD = 0.1

# file transfer chunk size
FILE_CHUNK_SIZE = 64 * 1024  # 64 KiB

class SecureServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.bb84 = QKDProtocol(key_length=KEY_LENGTH*4)
        self.e91 = EntanglementQKD(key_length=KEY_LENGTH*4)

    def _send_msg(self, conn, msg):
        data = pickle.dumps(msg)
        conn.sendall(len(data).to_bytes(4, 'big'))
        conn.sendall(data)

    def _recv_msg(self, conn):
        raw_len = conn.recv(4)
        if not raw_len:
            raise ConnectionError("Client disconnected")
        length = int.from_bytes(raw_len, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Client disconnected")
            data += chunk
        return pickle.loads(data)

    # ---------- New encrypted framing helpers ----------
    def _send_encrypted_frame(self, conn, aesgcm: AESGCM, plaintext_bytes: bytes):
        """
        Send a single encrypted frame: 4-byte length (plaintext) then nonce||ciphertext
        Each frame is decrypted independently.
        """
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext_bytes, None)
        payload = nonce + ct
        conn.sendall(struct.pack(">I", len(payload)))
        conn.sendall(payload)

    def _recv_encrypted_frame(self, conn, aesgcm: AESGCM):
        """
        Read one encrypted frame and return decrypted plaintext bytes.
        """
        raw = conn.recv(4)
        if not raw:
            return None
        length = struct.unpack(">I", raw)[0]
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed during frame")
            data += chunk
        nonce = data[:12]
        ct = data[12:]
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt

    # ---------- File transfer helpers ----------
    def send_encrypted_file(self, conn, aesgcm: AESGCM, filepath: str):
        """Server -> Client file send (server reads file and sends)"""
        if not os.path.isfile(filepath):
            self._send_encrypted_frame(conn, aesgcm, json.dumps({"type":"error","msg":"file_not_found"}).encode())
            return
        size = os.path.getsize(filepath)
        ctrl = {"type":"file_start", "name": os.path.basename(filepath), "size": size}
        self._send_encrypted_frame(conn, aesgcm, json.dumps(ctrl).encode())

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                # send raw chunk
                self._send_encrypted_frame(conn, aesgcm, chunk)
        # send end marker
        self._send_encrypted_frame(conn, aesgcm, json.dumps({"type":"file_end"}).encode())

    def recv_encrypted_file(self, conn, aesgcm: AESGCM, save_dir: str = "."):
        """
        Called when the next frames correspond to an incoming file.
        This function expects the first frame already read to be the file_start JSON.
        """
        # (This function expects to be called after having read the file_start control frame)
        # But we implement a loop here that will be used after we detect file_start externally.
        # Not used directly without detection; see usage in _handle_client.
        raise NotImplementedError("recv_encrypted_file is implemented inline in _handle_client")

    # ---------- Client handling ----------
    def _handle_client(self, conn, addr):
        print(f"✅ Connection from {addr}")
        try:
            print("🚀 Quantum key exchange...")

            # --- BB84 ---
            alice_bits = self.bb84.generate_random_bits(self.bb84.key_length)
            alice_bases = self.bb84.generate_random_bits(self.bb84.key_length)
            qc_bb84 = self.bb84.encode_qubits(alice_bits, alice_bases)
            self._send_msg(conn, qc_bb84)
            bob_bases = self._recv_msg(conn)

            # --- E91 ---
            alice_bases_e91 = [random.randint(0,1) for _ in range(self.e91.key_length)]
            e91_circuits = [self.e91._make_bell_pair_circuit(ab,0) for ab in alice_bases_e91]
            self._send_msg(conn, e91_circuits)
            bob_bases_e91 = self._recv_msg(conn)

            # --- SIFTING & QBER ---
            sift_bb84_idx = [i for i,(a,b) in enumerate(zip(alice_bases,bob_bases)) if a==b]
            sift_bb84_bits = [alice_bits[i] for i in sift_bb84_idx]
            self._send_msg(conn, {"sifted_indices_bb84": sift_bb84_idx})

            if len(sift_bb84_bits) < QBER_SAMPLE_SIZE:
                raise ValueError("Not enough sifted bits")

            qber_idx = random.sample(range(len(sift_bb84_bits)), QBER_SAMPLE_SIZE)
            qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
            self._send_msg(conn, {"qber_indices": list(qber_idx)})

            qber_sample_bob = self._recv_msg(conn)
            mismatches = sum(1 for i in qber_idx if qber_sample[i] != qber_sample_bob[i])
            error_rate = mismatches / QBER_SAMPLE_SIZE

            if error_rate > QBER_THRESHOLD:
                print(f"❌ Eavesdrop! QBER={error_rate:.2f}")
                self._send_msg(conn, {"status":"FAIL"})
                return

            self._send_msg(conn, {"status":"OK"})
            sift_e91_idx = [i for i,(a,b) in enumerate(zip(alice_bases_e91,bob_bases_e91)) if a==b]
            self._send_msg(conn, {"sifted_indices_e91": sift_e91_idx})

            # --- FINAL KEY ---
            final_bb84_bits = [bit for i,bit in enumerate(sift_bb84_bits) if i not in qber_idx]
            sift_e91_from_bob = self._recv_msg(conn)

            key1 = bits_to_bytes(final_bb84_bits)
            key2 = bits_to_bytes(sift_e91_from_bob)
            combined = brahmagupta_key_composition(key1,key2)
            final_key = ramanujan_inspired_kdf(combined)
            # ensure AES key size (16 bytes)
            aes_key = sha256(final_key).digest()[:16]
            print("🔐 Secure channel established!")

            aesgcm = AESGCM(aes_key)

            # New: use framed encrypted protocol that supports file transfer + messages
            print("You can now chat or use commands:\n - sendfile /path/to/file  (server->client)\n - getfile filename        (request client->server file)\n - exit")
            while True:
                # RECEIVE a single encrypted frame from client
                try:
                    pt = self._recv_encrypted_frame(conn, aesgcm)
                except ConnectionError:
                    break
                if pt is None:
                    break

                # try parse as JSON control
                handled = False
                try:
                    j = json.loads(pt.decode())
                    if isinstance(j, dict) and j.get("type") == "file_start":
                        # incoming file from client -> server
                        fname = j.get("name", "received.file")
                        fsize = j.get("size", 0)
                        save_path = os.path.join(".", fname)
                        print(f"Receiving file from client: {fname} ({fsize} bytes) -> saving to {save_path}")
                        with open(save_path, "wb") as wf:
                            while True:
                                chunk_pt = self._recv_encrypted_frame(conn, aesgcm)
                                if chunk_pt is None:
                                    raise ConnectionError("Connection closed while receiving file")
                                # check for control
                                try:
                                    maybe = json.loads(chunk_pt.decode())
                                    if isinstance(maybe, dict) and maybe.get("type") == "file_end":
                                        print("File receive complete.")
                                        break
                                except Exception:
                                    # not JSON -> raw chunk
                                    wf.write(chunk_pt)
                                    continue
                        handled = True
                    elif isinstance(j, dict) and j.get("type") == "file_request":
                        # client asked server to send a file to the client
                        req_name = j.get("name")
                        print(f"Client requested server file: {req_name}")
                        # try send it
                        filepath = os.path.join(".", req_name)
                        if os.path.isfile(filepath):
                            self.send_encrypted_file(conn, aesgcm, filepath)
                        else:
                            self._send_encrypted_frame(conn, aesgcm, json.dumps({"type":"error","msg":"file_not_found"}).encode())
                        handled = True
                    elif isinstance(j, dict) and j.get("type") == "error":
                        print("Client error:", j.get("msg"))
                        handled = True
                except json.JSONDecodeError:
                    pass

                if handled:
                    continue

                # otherwise treat as normal chat plaintext message
                msg = pt.decode()
                print(f"\nClient: {msg}")
                # allow server operator to input commands or reply
                resp = input("You: ").strip()
                if resp.startswith("sendfile "):
                    # operator wants to send a file to client
                    path = resp[len("sendfile "):].strip()
                    if os.path.isfile(path):
                        print(f"Sending {path} to client...")
                        self.send_encrypted_file(conn, aesgcm, path)
                    else:
                        print("File not found.")
                        # send an error control
                        self._send_encrypted_frame(conn, aesgcm, json.dumps({"type":"error","msg":"file_not_found"}).encode())
                    continue
                if resp.startswith("getfile "):
                    # ask client to send its file named X
                    name = resp[len("getfile "):].strip()
                    req = {"type":"file_request","name": name}
                    self._send_encrypted_frame(conn, aesgcm, json.dumps(req).encode())
                    # server will then wait for incoming file frames in the loop naturally
                    continue
                if resp.lower() == "exit":
                    break
                # otherwise simple message
                self._send_encrypted_frame(conn, aesgcm, resp.encode())

        except Exception as e:
            print(f"Error with {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection closed: {addr}")

    def start(self):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind((self.host,self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_client, args=(conn,addr)).start()

if __name__=="__main__":
    SecureServer(HOST,PORT).start()
