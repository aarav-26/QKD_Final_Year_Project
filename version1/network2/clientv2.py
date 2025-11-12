import socket
import pickle
import random
import os
import json
import struct
from qiskit_aer import AerSimulator
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256

from quantum_key_distribution.brahmagupta import brahmagupta_key_composition
from quantum_key_distribution.ramanujan import ramanujan_inspired_kdf, bits_to_bytes

HOST = 'localhost'
PORT = 65432

# same chunk size as server
FILE_CHUNK_SIZE = 64 * 1024

class SecureClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.backend = AerSimulator()

    def _send_msg(self, s, msg):
        data = pickle.dumps(msg)
        s.sendall(len(data).to_bytes(4,'big'))
        s.sendall(data)

    def _recv_msg(self, s):
        raw_len = s.recv(4)
        if not raw_len:
            raise ConnectionError("Server disconnected")
        length = int.from_bytes(raw_len,'big')
        data = b''
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk: raise ConnectionError
            data += chunk
        return pickle.loads(data)

    # ---------- encrypted framing helpers ----------
    def _send_encrypted_frame(self, s: socket.socket, aesgcm: AESGCM, plaintext_bytes: bytes):
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext_bytes, None)
        payload = nonce + ct
        s.sendall(struct.pack(">I", len(payload)))
        s.sendall(payload)

    def _recv_encrypted_frame(self, s: socket.socket, aesgcm: AESGCM):
        raw = s.recv(4)
        if not raw:
            return None
        length = struct.unpack(">I", raw)[0]
        data = b''
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed during frame")
            data += chunk
        nonce = data[:12]
        ct = data[12:]
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt

    # ---------- file helpers ----------
    def send_encrypted_file(self, s: socket.socket, aesgcm: AESGCM, filepath: str):
        if not os.path.isfile(filepath):
            self._send_encrypted_frame(s, aesgcm, json.dumps({"type":"error","msg":"file_not_found"}).encode())
            return
        size = os.path.getsize(filepath)
        ctrl = {"type":"file_start", "name": os.path.basename(filepath), "size": size}
        self._send_encrypted_frame(s, aesgcm, json.dumps(ctrl).encode())

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                self._send_encrypted_frame(s, aesgcm, chunk)

        self._send_encrypted_frame(s, aesgcm, json.dumps({"type":"file_end"}).encode())

    # ---------- entanglement measurement helper (your original) ----------
    def _measure_entangled_qubits(self, circuits, bases):
        bits = []
        for i,qc in enumerate(circuits):
            if bases[i]==1: qc.h(1)
            qc.measure(1,0)
            result = self.backend.run(qc,shots=1,memory=True).result()
            bits.append(int(result.get_memory(qc)[0]))
        return bits

    def start(self):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # --- BB84 ---
            qc_bb84 = self._recv_msg(s)
            bob_bases = [random.randint(0,1) for _ in range(qc_bb84.num_qubits)]
            self._send_msg(s, bob_bases)
            for i,b in enumerate(bob_bases):
                if b==1: qc_bb84.h(i)
            qc_bb84.measure(range(len(bob_bases)), range(len(bob_bases)))
            result = self.backend.run(qc_bb84,shots=1,memory=True).result()
            measured_bits_bb84 = [int(b) for b in result.get_memory(qc_bb84)[0][::-1]]

            # --- E91 ---
            e91_circuits = self._recv_msg(s)
            bob_bases_e91 = [random.randint(0,1) for _ in range(len(e91_circuits))]
            self._send_msg(s,bob_bases_e91)
            measured_bits_e91 = self._measure_entangled_qubits(e91_circuits, bob_bases_e91)

            # --- SIFTING & QBER ---
            sift_bb84_info = self._recv_msg(s)
            sift_idx_bb84 = sift_bb84_info['sifted_indices_bb84']
            sift_bb84_bits = [measured_bits_bb84[i] for i in sift_idx_bb84]

            qber_info = self._recv_msg(s)
            qber_idx = qber_info['qber_indices']
            qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
            self._send_msg(s,qber_sample)

            status = self._recv_msg(s)
            if status['status']=="FAIL":
                print("❌ QBER failed. Abort."); return
            print("QBER check passed.")

            sift_e91_info = self._recv_msg(s)
            sift_idx_e91 = sift_e91_info['sifted_indices_e91']
            sift_e91_bits = [measured_bits_e91[i] for i in sift_idx_e91]

            # --- FINAL KEY ---
            final_bb84_bits = [b for i,b in enumerate(sift_bb84_bits) if i not in qber_idx]
            self._send_msg(s, sift_e91_bits)

            key1 = bits_to_bytes(final_bb84_bits)
            key2 = bits_to_bytes(sift_e91_bits)
            combined = brahmagupta_key_composition(key1,key2)
            final_key = ramanujan_inspired_kdf(combined)
            aes_key = sha256(final_key).digest()[:16]

            print("🔐 Secure channel established!")
            aesgcm = AESGCM(aes_key)

            print("You can now chat or use commands:\n - sendfile /path/to/file  (client->server)\n - getfile filename        (request server->client file)\n - exit")
            while True:
                # Non-blocking pattern is complex; we'll just take input then process incoming response(s)
                msg = input("You: ").strip()
                if msg.lower() == "exit":
                    break
                if msg.startswith("sendfile "):
                    path = msg[len("sendfile "):].strip()
                    if os.path.isfile(path):
                        print(f"Sending file {path} to server...")
                        self.send_encrypted_file(s, aesgcm, path)
                    else:
                        print("File not found.")
                        self._send_encrypted_frame(s, aesgcm, json.dumps({"type":"error","msg":"file_not_found"}).encode())
                    continue
                if msg.startswith("getfile "):
                    # request server to send a file to us
                    name = msg[len("getfile "):].strip()
                    req = {"type":"file_request","name": name}
                    self._send_encrypted_frame(s, aesgcm, json.dumps(req).encode())
                    # now wait for incoming file frames — handled in receive loop below
                    # fall through to receive step
                else:
                    # normal chat message
                    self._send_encrypted_frame(s, aesgcm, msg.encode())

                # after sending something, attempt to receive server responses until there's none immediately
                # We'll do one blocking receive (server responds). In a production client you'd use select/poll or threads.
                try:
                    pt = self._recv_encrypted_frame(s, aesgcm)
                except ConnectionError:
                    print("Connection closed.")
                    break
                if pt is None:
                    print("Connection closed by server.")
                    break

                # check if control JSON
                handled = False
                try:
                    j = json.loads(pt.decode())
                    if isinstance(j, dict) and j.get("type") == "file_start":
                        fname = j.get("name", "received.file")
                        fsize = j.get("size", 0)
                        save_path = os.path.join(".", fname)
                        print(f"Receiving file from server: {fname} ({fsize} bytes) -> saving to {save_path}")
                        with open(save_path, "wb") as wf:
                            while True:
                                chunk_pt = self._recv_encrypted_frame(s, aesgcm)
                                if chunk_pt is None:
                                    raise ConnectionError("Connection closed while receiving file")
                                # check if this is file_end
                                try:
                                    maybe = json.loads(chunk_pt.decode())
                                    if isinstance(maybe, dict) and maybe.get("type") == "file_end":
                                        print("File receive complete.")
                                        break
                                except Exception:
                                    wf.write(chunk_pt)
                                    continue
                        handled = True
                    elif isinstance(j, dict) and j.get("type") == "error":
                        print("Server error:", j.get("msg"))
                        handled = True
                except json.JSONDecodeError:
                    pass

                if handled:
                    continue

                # otherwise plaintext chat response
                print("Server:", pt.decode())

if __name__=="__main__":
    SecureClient(HOST,PORT).start()
