# streamlit_secure_client.py
# Streamlit UI for the SecureClient (BB84+E91 QKD + AES-GCM encrypted chat & file transfer)
# Option 1: background thread keeps the connection alive and receives messages/files in real-time.

import streamlit as st
import threading
import queue
import time
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

# -------------------- Config --------------------
HOST_DEFAULT = 'localhost'
PORT_DEFAULT = 65432
FILE_CHUNK_SIZE = 64 * 1024
AUTORELOAD_SECONDS = 2  # UI refresh interval
RECV_DIR = "received_files"
os.makedirs(RECV_DIR, exist_ok=True)

# -------------------- SecureClient (adapted for UI) --------------------
class SecureClient:
    """
    Adapted SecureClient that exposes connect(), send_message(), send_file(), request_file(), close()
    Internals are kept faithful to your original logic (QKD handshake, BB84+E91, AES-GCM framing, file transfer formats).
    """
    def __init__(self, host, port, recv_queue: queue.Queue, file_save_dir=RECV_DIR):
        self.host = host
        self.port = port
        self.backend = AerSimulator()
        self.s = None
        self.aesgcm = None
        self.recv_queue = recv_queue  # queue to push incoming messages/events to UI
        self.running = False
        self.file_save_dir = file_save_dir

    # --- low-level pickle message helpers (used during QKD handshake) ---
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

    # --- encrypted framing helpers ---
    def _send_encrypted_frame(self, plaintext_bytes: bytes):
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext_bytes, None)
        payload = nonce + ct
        self.s.sendall(struct.pack(">I", len(payload)))
        self.s.sendall(payload)

    def _recv_encrypted_frame_raw(self):
        raw = self.s.recv(4)
        if not raw:
            return None
        length = struct.unpack(">I", raw)[0]
        data = b''
        while len(data) < length:
            chunk = self.s.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed during frame")
            data += chunk
        return data

    def _recv_encrypted_frame(self):
        data = self._recv_encrypted_frame_raw()
        if data is None:
            return None
        nonce = data[:12]
        ct = data[12:]
        pt = self.aesgcm.decrypt(nonce, ct, None)
        return pt

    # --- file send helper (client -> server) ---
    def send_encrypted_file(self, filepath: str):
        if not os.path.isfile(filepath):
            # send error control
            self._send_encrypted_frame(json.dumps({"type":"error","msg":"file_not_found"}).encode())
            return
        size = os.path.getsize(filepath)
        ctrl = {"type":"file_start", "name": os.path.basename(filepath), "size": size}
        self._send_encrypted_frame(json.dumps(ctrl).encode())

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                self._send_encrypted_frame(chunk)

        self._send_encrypted_frame(json.dumps({"type":"file_end"}).encode())

    # --- minimal entanglement measurement helper (kept from original) ---
    def _measure_entangled_qubits(self, circuits, bases):
        bits = []
        for i,qc in enumerate(circuits):
            if bases[i]==1:
                qc.h(1)
            qc.measure(1,0)
            result = self.backend.run(qc,shots=1,memory=True).result()
            bits.append(int(result.get_memory(qc)[0]))
        return bits

    # --- high-level connect & handshake (runs the QKD protocol with server) ---
    def connect(self, timeout=10):
        """
        Connect to server and perform QKD handshake (BB84 + E91) to derive AES-GCM key.
        On success: sets self.s and self.aesgcm and returns True.
        Raises on failure.
        """
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect((self.host, self.port))

        # --- BB84 ---
        qc_bb84 = self._recv_msg(self.s)
        bob_bases = [random.randint(0,1) for _ in range(qc_bb84.num_qubits)]
        self._send_msg(self.s, bob_bases)
        for i,b in enumerate(bob_bases):
            if b==1: qc_bb84.h(i)
        qc_bb84.measure(range(len(bob_bases)), range(len(bob_bases)))
        result = self.backend.run(qc_bb84,shots=1,memory=True).result()
        measured_bits_bb84 = [int(b) for b in result.get_memory(qc_bb84)[0][::-1]]

        # --- E91 ---
        e91_circuits = self._recv_msg(self.s)
        bob_bases_e91 = [random.randint(0,1) for _ in range(len(e91_circuits))]
        self._send_msg(self.s,bob_bases_e91)
        measured_bits_e91 = self._measure_entangled_qubits(e91_circuits, bob_bases_e91)

        # --- SIFTING & QBER ---
        sift_bb84_info = self._recv_msg(self.s)
        sift_idx_bb84 = sift_bb84_info['sifted_indices_bb84']
        sift_bb84_bits = [measured_bits_bb84[i] for i in sift_idx_bb84]

        qber_info = self._recv_msg(self.s)
        qber_idx = qber_info['qber_indices']
        qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
        self._send_msg(self.s,qber_sample)

        status = self._recv_msg(self.s)
        if status['status']=="FAIL":
            raise ConnectionError("QBER failed - possible eavesdropping")

        sift_e91_info = self._recv_msg(self.s)
        sift_idx_e91 = sift_e91_info['sifted_indices_e91']
        sift_e91_bits = [measured_bits_e91[i] for i in sift_idx_e91]

        # --- FINAL KEY ---
        final_bb84_bits = [b for i,b in enumerate(sift_bb84_bits) if i not in qber_idx]
        self._send_msg(self.s, sift_e91_bits)

        key1 = bits_to_bytes(final_bb84_bits)
        key2 = bits_to_bytes(sift_e91_bits)
        combined = brahmagupta_key_composition(key1,key2)
        final_key = ramanujan_inspired_kdf(combined)
        aes_key = sha256(final_key).digest()[:16]

        self.aesgcm = AESGCM(aes_key)
        self.s.settimeout(None)
        self.running = True

        # start receiver thread
        threading.Thread(target=self._receiver_loop, daemon=True).start()
        return True

    # --- receiver loop: read frames, detect file transfers and JSON controls, push events to recv_queue ---
    def _receiver_loop(self):
        try:
            while self.running:
                try:
                    pt = self._recv_encrypted_frame()
                except ConnectionError:
                    self.recv_queue.put(("system","connection_closed"))
                    break
                if pt is None:
                    self.recv_queue.put(("system","connection_closed"))
                    break

                # try parse as JSON control
                handled = False
                try:
                    j = json.loads(pt.decode())
                    if isinstance(j, dict) and j.get("type") == "file_start":
                        fname = j.get("name", "received.file")
                        fsize = j.get("size", 0)
                        save_path = os.path.join(self.file_save_dir, fname)
                        # ensure unique filename
                        base, ext = os.path.splitext(save_path)
                        idx = 1
                        while os.path.exists(save_path):
                            save_path = f"{base}_{idx}{ext}"
                            idx += 1
                        with open(save_path, "wb") as wf:
                            while True:
                                chunk_pt = self._recv_encrypted_frame()
                                if chunk_pt is None:
                                    raise ConnectionError("Connection closed while receiving file")
                                # check if this is file_end
                                try:
                                    maybe = json.loads(chunk_pt.decode())
                                    if isinstance(maybe, dict) and maybe.get("type") == "file_end":
                                        self.recv_queue.put(("file", {"path": save_path, "name": os.path.basename(save_path), "size": fsize}))
                                        break
                                except Exception:
                                    wf.write(chunk_pt)
                                    continue
                        handled = True
                    elif isinstance(j, dict) and j.get("type") == "error":
                        self.recv_queue.put(("error", j.get("msg")))
                        handled = True
                except json.JSONDecodeError:
                    pass

                if handled:
                    continue

                # otherwise plaintext chat response
                try:
                    txt = pt.decode()
                except Exception:
                    txt = repr(pt)
                self.recv_queue.put(("msg", txt))
        finally:
            self.running = False

    # --- public send methods used by UI ---
    def send_message(self, msg: str):
        if not self.running:
            raise ConnectionError("Not connected")
        self._send_encrypted_frame(msg.encode())

    def request_file(self, name: str):
        if not self.running:
            raise ConnectionError("Not connected")
        req = {"type":"file_request","name": name}
        self._send_encrypted_frame(json.dumps(req).encode())

    def close(self):
        self.running = False
        try:
            if self.s:
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
        except Exception:
            pass

# -------------------- Streamlit UI --------------------
st.set_page_config(page_title="Quantum Secure Chat - Streamlit UI", layout="wide")

# session state
if 'client' not in st.session_state:
    st.session_state.client = None
if 'recv_queue' not in st.session_state:
    st.session_state.recv_queue = queue.Queue()
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'received_files' not in st.session_state:
    st.session_state.received_files = []
if 'connecting' not in st.session_state:
    st.session_state.connecting = False
if 'connected' not in st.session_state:
    st.session_state.connected = False

# header
st.markdown("<h1 style='color:#0f172a'>🔐 Quantum Secure Chat</h1>", unsafe_allow_html=True)
st.markdown("""
Secure chat using **BB84 + E91** quantum key distribution to derive an AES-GCM key.

Features: real-time background receiver thread, encrypted file transfer, message history, download received files.
""")

# left column: controls
left, right = st.columns([1,2])
with left:
    st.subheader("Connection")
    host = st.text_input("Server host", value=HOST_DEFAULT)
    port = st.number_input("Server port", value=PORT_DEFAULT, step=1)
    if not st.session_state.connected:
        if st.button("🔗 Connect") and not st.session_state.connecting:
            st.session_state.connecting = True
            st.session_state.messages.append(("system","Connecting..."))

            def _connect_thread():
                try:
                    client = SecureClient(host, port, st.session_state.recv_queue)
                    client.connect()
                    st.session_state.client = client
                    st.session_state.connected = True
                    st.session_state.messages.append(("system","Connected & secure channel established."))
                except Exception as e:
                    st.session_state.messages.append(("system", f"Connection failed: {e}"))
                finally:
                    st.session_state.connecting = False

            threading.Thread(target=_connect_thread, daemon=True).start()
    else:
        if st.button("🔒 Disconnect"):
            try:
                st.session_state.client.close()
            except Exception:
                pass
            st.session_state.client = None
            st.session_state.connected = False
            st.session_state.messages.append(("system","Disconnected by user."))

    st.markdown("---")
    st.subheader("Send File")
    upload = st.file_uploader("Choose file to send", key='uploader')
    if upload is not None:
        fname = upload.name
        temp_path = os.path.join("uploads", fname)
        os.makedirs("uploads", exist_ok=True)
        with open(temp_path, "wb") as wf:
            wf.write(upload.getbuffer())
        st.write(f"Prepared: {fname}")
        if st.button("Send file"):
            if st.session_state.connected and st.session_state.client:
                threading.Thread(target=lambda p=temp_path: st.session_state.client.send_encrypted_file(p), daemon=True).start()
                st.session_state.messages.append(("me", f"Sent file: {fname}"))
            else:
                st.warning("Not connected")

    st.markdown("---")
    st.subheader("Request file from server")
    req_name = st.text_input("Filename to request from server")
    if st.button("Request file"):
        if st.session_state.connected and st.session_state.client:
            try:
                st.session_state.client.request_file(req_name)
                st.session_state.messages.append(("me", f"Requested file: {req_name}"))
            except Exception as e:
                st.error(f"Request failed: {e}")
        else:
            st.warning("Not connected")

    st.markdown("---")
    st.subheader("Status")
    if st.session_state.connected:
        st.success("Connected & secure 🔐")
    elif st.session_state.connecting:
        st.info("Connecting...")
    else:
        st.error("Not connected")

# right column: chat
with right:
    st.subheader("Chat Window")
    chat_box = st.container()

    # message input and send
    col_inp, col_send = st.columns([5,1])
    message_text = col_inp.text_input("Message", key='msg_input')
    if col_send.button("Send"):
        if not st.session_state.connected or not st.session_state.client:
            st.warning("Not connected")
        else:
            try:
                st.session_state.client.send_message(message_text)
                st.session_state.messages.append(("me", message_text))
                st.session_state['msg_input'] = ''
            except Exception as e:
                st.error(f"Send failed: {e}")

    # display messages
    with chat_box:
        for who, txt in st.session_state.messages[-200:]:
            if who == 'me':
                st.markdown(f"<div style='text-align:right;background:#e6fffa;padding:8px;border-radius:8px;margin:6px 0'>{txt}</div>", unsafe_allow_html=True)
            elif who == 'server' or who == 'msg':
                st.markdown(f"<div style='text-align:left;background:#fff1f2;padding:8px;border-radius:8px;margin:6px 0'>{txt}</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div style='text-align:center;color:#888;margin:6px 0'>[{who}] {txt}</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("Received files")
    # list files discovered in session_state.received_files
    for f in st.session_state.received_files:
        cols = st.columns([4,1])
        cols[0].write(f"{f['name']} ({f['size']} bytes)")
        cols[1].download_button(label="Download", data=open(f['path'], 'rb').read(), file_name=f['name'])

# -------------------- background: pull events from recv_queue into session_state --------------------
def _drain_recv_queue():
    q = st.session_state.recv_queue
    moved = False
    while not q.empty():
        evt, payload = q.get()
        moved = True
        if evt == 'msg':
            st.session_state.messages.append(("server", payload))
        elif evt == 'file':
            st.session_state.received_files.append(payload)
            st.session_state.messages.append(("server", f"Received file: {payload['name']} ({payload['size']} bytes) -> saved to {payload['path']}"))
        elif evt == 'error':
            st.session_state.messages.append(("system", f"Error: {payload}"))
        elif evt == 'system' and payload == 'connection_closed':
            st.session_state.messages.append(("system","Connection closed by remote"))
            if st.session_state.client:
                try:
                    st.session_state.client.close()
                except Exception:
                    pass
                st.session_state.client = None
            st.session_state.connected = False
    return moved

_drain_recv_queue()

# auto refresh so incoming messages appear in UI without manual reload
st_autorefresh = st.experimental_data_editor if False else None
# simple JS-based refresh (works across many Streamlit versions)
st.markdown(f"<script>setInterval(() => {{window.parent.postMessage({{type: 'streamlit:rerun'}}, '*')}}, {AUTORELOAD_SECONDS*1000});</script>", unsafe_allow_html=True)

# footer
st.markdown("<hr><div style='font-size:12px;color:#666'>Built with QKD handshake + AES-GCM encrypted frames. Keep server running and use this UI to chat securely.</div>", unsafe_allow_html=True)
