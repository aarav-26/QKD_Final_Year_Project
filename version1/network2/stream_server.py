# streamlit_secure_server.py
# Streamlit admin UI for SecureServer (wraps your SecureServer logic into a UI + background server)
# Keeps all QKD, E91, BB84, and framed AES-GCM functionality intact while removing blocking input() calls

import streamlit as st
import threading
import queue
import time
import os
import socket
import pickle
import random
import json
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256

# QKD modules (ensure these are available)
from quantum_key_distribution.bb84 import QKDProtocol
from quantum_key_distribution.entanglement_qkd import EntanglementQKD
from quantum_key_distribution.brahmagupta import brahmagupta_key_composition
from quantum_key_distribution.ramanujan import ramanujan_inspired_kdf, bits_to_bytes

HOST_DEFAULT = '0.0.0.0'
PORT_DEFAULT = 65432
FILE_CHUNK_SIZE = 64 * 1024
RECV_DIR = "server_received"
os.makedirs(RECV_DIR, exist_ok=True)

# -------------------- Helper: safe send/recv pickled --------------------

def send_pickle(conn, msg):
    data = pickle.dumps(msg)
    conn.sendall(len(data).to_bytes(4, 'big'))
    conn.sendall(data)


def recv_pickle(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        raise ConnectionError("Peer disconnected")
    length = int.from_bytes(raw_len, 'big')
    data = b''
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Peer disconnected")
        data += chunk
    return pickle.loads(data)

# -------------------- ClientSession: per-connection handler --------------------
class ClientSession:
    def __init__(self, conn, addr, server_obj):
        self.conn = conn
        self.addr = addr
        self.server = server_obj
        self.id = f"{addr[0]}:{addr[1]}"
        self.alive = True
        self.aesgcm = None
        self.send_queue = queue.Queue()  # operator -> client
        self.recv_queue = queue.Queue()  # client -> operator (for UI)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.lock = threading.Lock()

    # encrypted framing helpers using self.aesgcm
    def _send_encrypted_frame(self, plaintext_bytes: bytes):
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext_bytes, None)
        payload = nonce + ct
        self.conn.sendall(struct.pack(">I", len(payload)))
        self.conn.sendall(payload)

    def _recv_encrypted_frame(self):
        raw = self.conn.recv(4)
        if not raw:
            return None
        length = struct.unpack(">I", raw)[0]
        data = b''
        while len(data) < length:
            chunk = self.conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed during frame")
            data += chunk
        nonce = data[:12]
        ct = data[12:]
        pt = self.aesgcm.decrypt(nonce, ct, None)
        return pt

    def start(self):
        self.thread.start()

    def _run(self):
        """
        Perform QKD handshake (using server's QKD objects) and then enter a framed receive loop.
        The loop polls for incoming encrypted frames and also checks operator send_queue for outgoing messages.
        """
        try:
            # ---- QKD handshake with server's helpers -----
            bb84 = self.server.bb84
            e91 = self.server.e91

            # --- BB84: prepare and send circuits to client (Alice -> Bob style preserved) ---
            alice_bits = bb84.generate_random_bits(bb84.key_length)
            alice_bases = bb84.generate_random_bits(bb84.key_length)
            qc_bb84 = bb84.encode_qubits(alice_bits, alice_bases)
            send_pickle(self.conn, qc_bb84)
            bob_bases = recv_pickle(self.conn)

            # --- E91 ---
            alice_bases_e91 = [random.randint(0,1) for _ in range(e91.key_length)]
            e91_circuits = [e91._make_bell_pair_circuit(ab,0) for ab in alice_bases_e91]
            send_pickle(self.conn, e91_circuits)
            bob_bases_e91 = recv_pickle(self.conn)

            # --- SIFTING & QBER ---
            sift_bb84_idx = [i for i,(a,b) in enumerate(zip(alice_bases,bob_bases)) if a==b]
            sift_bb84_bits = [alice_bits[i] for i in sift_bb84_idx]
            send_pickle(self.conn, {"sifted_indices_bb84": sift_bb84_idx})

            if len(sift_bb84_bits) < self.server.QBER_SAMPLE_SIZE:
                raise ValueError("Not enough sifted bits")

            qber_idx = random.sample(range(len(sift_bb84_bits)), self.server.QBER_SAMPLE_SIZE)
            qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
            send_pickle(self.conn, {"qber_indices": list(qber_idx)})

            qber_sample_bob = recv_pickle(self.conn)
            mismatches = sum(1 for i in qber_idx if qber_sample[i] != qber_sample_bob[i])
            error_rate = mismatches / self.server.QBER_SAMPLE_SIZE

            if error_rate > self.server.QBER_THRESHOLD:
                send_pickle(self.conn, {"status":"FAIL"})
                raise ConnectionError(f"QBER too high: {error_rate:.2f}")

            send_pickle(self.conn, {"status":"OK"})
            sift_e91_idx = [i for i,(a,b) in enumerate(zip(alice_bases_e91,bob_bases_e91)) if a==b]
            send_pickle(self.conn, {"sifted_indices_e91": sift_e91_idx})

            final_bb84_bits = [bit for i,bit in enumerate(sift_bb84_bits) if i not in qber_idx]
            sift_e91_from_bob = recv_pickle(self.conn)

            key1 = bits_to_bytes(final_bb84_bits)
            key2 = bits_to_bytes(sift_e91_from_bob)
            combined = brahmagupta_key_composition(key1,key2)
            final_key = ramanujan_inspired_kdf(combined)
            aes_key = sha256(final_key).digest()[:16]

            self.aesgcm = AESGCM(aes_key)
            self.conn.settimeout(0.5)  # non-blocking-ish for the loop
            self.recv_queue.put(("system","qkd_ok"))

            # ---- main framed loop ----
            while self.alive:
                # first: handle outgoing operator messages if any
                try:
                    out = self.send_queue.get_nowait()
                except queue.Empty:
                    out = None

                if out is not None:
                    typ = out.get('type')
                    if typ == 'message':
                        self._send_encrypted_frame(out['data'].encode())
                    elif typ == 'send_file':
                        filepath = out['path']
                        # use server helper to stream file frames
                        if os.path.isfile(filepath):
                            size = os.path.getsize(filepath)
                            ctrl = {"type":"file_start","name": os.path.basename(filepath), "size": size}
                            self._send_encrypted_frame(json.dumps(ctrl).encode())
                            with open(filepath, 'rb') as f:
                                while True:
                                    chunk = f.read(FILE_CHUNK_SIZE)
                                    if not chunk:
                                        break
                                    self._send_encrypted_frame(chunk)
                            self._send_encrypted_frame(json.dumps({"type":"file_end"}).encode())
                        else:
                            self._send_encrypted_frame(json.dumps({"type":"error","msg":"file_not_found"}).encode())
                    elif typ == 'request_file':
                        name = out.get('name')
                        ctrl = {"type":"file_request","name": name}
                        self._send_encrypted_frame(json.dumps(ctrl).encode())

                # then: try receive an encrypted frame from client
                try:
                    # non-blocking receive due to timeout
                    raw = self.conn.recv(4)
                    if not raw:
                        raise ConnectionError("peer disconnected")
                    length = struct.unpack(">I", raw)[0]
                    data = b''
                    while len(data) < length:
                        chunk = self.conn.recv(length - len(data))
                        if not chunk:
                            raise ConnectionError("Connection closed during frame")
                        data += chunk
                    nonce = data[:12]
                    ct = data[12:]
                    pt = self.aesgcm.decrypt(nonce, ct, None)
                except socket.timeout:
                    # no incoming frame this iteration
                    continue
                except ConnectionError:
                    break
                except Exception as e:
                    # decryption or unexpected error
                    self.recv_queue.put(("error", str(e)))
                    break

                # process pt
                handled = False
                try:
                    j = json.loads(pt.decode())
                    if isinstance(j, dict) and j.get('type') == 'file_start':
                        fname = j.get('name', 'received.file')
                        fsize = j.get('size', 0)
                        save_path = os.path.join(RECV_DIR, fname)
                        base, ext = os.path.splitext(save_path)
                        idx = 1
                        while os.path.exists(save_path):
                            save_path = f"{base}_{idx}{ext}"
                            idx += 1
                        with open(save_path, 'wb') as wf:
                            while True:
                                # read next frame
                                raw2 = self.conn.recv(4)
                                if not raw2:
                                    raise ConnectionError("Connection closed during file recv")
                                length2 = struct.unpack(">I", raw2)[0]
                                data2 = b''
                                while len(data2) < length2:
                                    chunk2 = self.conn.recv(length2 - len(data2))
                                    if not chunk2:
                                        raise ConnectionError("Connection closed during file recv")
                                    data2 += chunk2
                                nonce2 = data2[:12]
                                ct2 = data2[12:]
                                pt2 = self.aesgcm.decrypt(nonce2, ct2, None)
                                try:
                                    maybe = json.loads(pt2.decode())
                                    if isinstance(maybe, dict) and maybe.get('type') == 'file_end':
                                        # done
                                        self.recv_queue.put(("file", {"path": save_path, "name": os.path.basename(save_path), "size": fsize}))
                                        break
                                except Exception:
                                    wf.write(pt2)
                                    continue
                        handled = True
                    elif isinstance(j, dict) and j.get('type') == 'file_request':
                        req_name = j.get('name')
                        # operator may choose to fulfill via UI; for now auto-send if exists in cwd
                        filepath = os.path.join('.', req_name)
                        if os.path.isfile(filepath):
                            # send file
                            size = os.path.getsize(filepath)
                            ctrl = {"type":"file_start","name": os.path.basename(filepath), "size": size}
                            self._send_encrypted_frame(json.dumps(ctrl).encode())
                            with open(filepath, 'rb') as f:
                                while True:
                                    chunk = f.read(FILE_CHUNK_SIZE)
                                    if not chunk:
                                        break
                                    self._send_encrypted_frame(chunk)
                            self._send_encrypted_frame(json.dumps({"type":"file_end"}).encode())
                        else:
                            self._send_encrypted_frame(json.dumps({"type":"error","msg":"file_not_found"}).encode())
                        handled = True
                    elif isinstance(j, dict) and j.get('type') == 'error':
                        self.recv_queue.put(("error", j.get('msg')))
                        handled = True
                except json.JSONDecodeError:
                    pass

                if handled:
                    continue

                # otherwise it's a plaintext chat message
                try:
                    txt = pt.decode()
                except Exception:
                    txt = repr(pt)
                self.recv_queue.put(("msg", txt))

        except Exception as e:
            self.recv_queue.put(("error", str(e)))
        finally:
            self.alive = False
            try:
                self.conn.close()
            except Exception:
                pass
            self.recv_queue.put(("system","closed"))

# -------------------- Server object that listens for incoming connections --------------------
class StreamlitSecureServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_sock = None
        self.accept_thread = None
        self.running = False
        self.sessions = {}  # id -> ClientSession

        # reuse original QKD objects
        self.bb84 = QKDProtocol(key_length=128*4)
        self.e91 = EntanglementQKD(key_length=128*4)
        self.QBER_SAMPLE_SIZE = 32
        self.QBER_THRESHOLD = 0.1

    def start(self):
        if self.running:
            return
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen()
        self.running = True
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                sess = ClientSession(conn, addr, self)
                self.sessions[sess.id] = sess
                sess.start()
            except Exception:
                time.sleep(0.1)

    def stop(self):
        self.running = False
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        # close sessions
        for s in list(self.sessions.values()):
            s.alive = False
            try:
                s.conn.close()
            except Exception:
                pass
        self.sessions.clear()

# -------------------- Streamlit UI --------------------
st.set_page_config(page_title="Quantum Secure Server - Admin", layout="wide")
if 'server' not in st.session_state:
    st.session_state.server = None
if 'logs' not in st.session_state:
    st.session_state.logs = []

st.title("🔐 Quantum Secure Server - Admin UI")
left, right = st.columns([1,2])
with left:
    st.subheader("Server Controls")
    host = st.text_input("Host to bind", value=HOST_DEFAULT)
    port = st.number_input("Port", value=PORT_DEFAULT, step=1)
    if st.session_state.server is None or not st.session_state.server.running:
        if st.button("Start Server"):
            srv = StreamlitSecureServer(host, port)
            srv.start()
            st.session_state.server = srv
            st.session_state.logs.append(("system","Server started"))
    else:
        if st.button("Stop Server"):
            st.session_state.server.stop()
            st.session_state.logs.append(("system","Server stopped"))
            st.session_state.server = None

    st.markdown("---")
    st.subheader("Select Client")
    client_ids = list(st.session_state.server.sessions.keys()) if st.session_state.server else []
    selected = st.selectbox("Connected clients", options=["-- none --"] + client_ids)

    st.markdown("---")
    st.subheader("Send Message / File to Client")
    message = st.text_area("Message to client")
    file_to_send = st.file_uploader("File to send to selected client")
    if st.button("Send Message"):
        if selected and selected != "-- none --":
            sess = st.session_state.server.sessions[selected]
            sess.send_queue.put({'type':'message', 'data': message})
            st.session_state.logs.append(("out", f"To {selected}: {message}"))
        else:
            st.warning("Select a client first")
    if file_to_send is not None and st.button("Send File"):
        if selected and selected != "-- none --":
            tmp = os.path.join('server_uploads', file_to_send.name)
            os.makedirs('server_uploads', exist_ok=True)
            with open(tmp, 'wb') as wf:
                wf.write(file_to_send.getbuffer())
            sess = st.session_state.server.sessions[selected]
            sess.send_queue.put({'type':'send_file', 'path': tmp})
            st.session_state.logs.append(("out", f"Sent file to {selected}: {file_to_send.name}"))
        else:
            st.warning("Select a client first")

with right:
    st.subheader("Activity & Messages")
    # drain each client's recv_queue into server logs
    if st.session_state.server:
        for cid, sess in list(st.session_state.server.sessions.items()):
            while not sess.recv_queue.empty():
                evt, payload = sess.recv_queue.get()
                if evt == 'msg':
                    st.session_state.logs.append(("in", f"From {cid}: {payload}"))
                elif evt == 'file':
                    st.session_state.logs.append(("in", f"Received file from {cid}: {payload['name']} -> saved {payload['path']}"))
                elif evt == 'error':
                    st.session_state.logs.append(("error", f"{cid}: {payload}"))
                elif evt == 'system' and payload == 'qkd_ok':
                    st.session_state.logs.append(("system", f"{cid}: QKD handshake completed"))
                elif evt == 'system' and payload == 'closed':
                    st.session_state.logs.append(("system", f"{cid}: connection closed"))
                    try:
                        del st.session_state.server.sessions[cid]
                    except Exception:
                        pass

    # show logs in reverse chronological order (most recent on top)
    for tag, line in st.session_state.logs[-200:]:
        if tag == 'in':
            st.markdown(f"<div style='text-align:left;background:#fff1f2;padding:8px;border-radius:8px;margin:6px 0'>{line}</div>", unsafe_allow_html=True)
        elif tag == 'out':
            st.markdown(f"<div style='text-align:right;background:#e6fffa;padding:8px;border-radius:8px;margin:6px 0'>{line}</div>", unsafe_allow_html=True)
        elif tag == 'error':
            st.markdown(f"<div style='text-align:center;color:#b00020;padding:6px'>{line}</div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<div style='text-align:center;color:#666;padding:4px'>{line}</div>", unsafe_allow_html=True)

st.markdown("---")
st.caption("This admin UI wraps the original server logic: QKD (BB84+E91) handshake is performed for each client, then a framed AES-GCM channel is used for messages and file transfers.")
