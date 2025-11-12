# quantum_key_distribution/entanglement_qkd.py
import math
import random
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import itertools

class EntanglementQKD:
    """
    Simple entanglement-based QKD (E91-style) key generator.
    - Uses Bell pairs (|Φ+>).
    - Alice and Bob choose random bases: 0 = Z, 1 = X.
    - Keep rounds where bases match to build final key.
    - Batches circuits for better performance.
    """

    def __init__(self, key_length=256, batch_size=64):
        self.key_length = key_length
        self.backend = AerSimulator()
        self.rng = random.SystemRandom()
        self.batch_size = max(1, int(batch_size))

        # last-run raw values (for debugging/inspection)
        self.alice_bases = []
        self.bob_bases = []
        self.alice_bits = []
        self.bob_bits = []

    def _make_bell_pair_circuit(self, alice_basis, bob_basis):
        """
        Create a circuit producing a Bell pair and measuring Alice (qubit 0)
        and Bob (qubit 1) in the requested basis.
        Input:
          alice_basis, bob_basis: 0 for Z-basis, 1 for X-basis
        Return:
          QuantumCircuit(2,2) with measurements: c0 <- Alice, c1 <- Bob
        """
        qc = QuantumCircuit(2, 2)
        # Create |Φ+> Bell state
        qc.h(0)
        qc.cx(0, 1)

        # If basis == X, apply H before measuring (measure in X by rotating then Z-measure).
        # Instead of H we use RY(-pi/2) equivalently; H works fine here (standard).
        if alice_basis == 1:
            qc.h(0)
        if bob_basis == 1:
            qc.h(1)

        # Measure qubit0 -> c0 (Alice), qubit1 -> c1 (Bob)
        qc.measure(0, 0)
        qc.measure(1, 1)
        return qc

    def _run_batch(self, circuits):
        """
        Run a list of circuits (each with shots=1) and return list of (a_bit, b_bit, raw_bitstring).
        Qiskit returns bitstrings with classical registers ordered left-to-right; we used c0 then c1,
        but the returned string is typically 'c1c0' (leftmost is c1). To avoid confusion we parse explicitly.
        """
        job = self.backend.run(circuits, shots=1)
        result = job.result()
        outcomes = []
        for i in range(len(circuits)):
            counts = result.get_counts(i)
            bitstr = list(counts.keys())[0]  # e.g. '10'
            # bitstring returned as classical registers in order they are added to circuit;
            # we mapped measure(0,0) then measure(1,1). To be safe: reverse so index 0 -> c0 (Alice).
            rev = bitstr[::-1]
            a_bit = int(rev[0])
            b_bit = int(rev[1])
            outcomes.append((a_bit, b_bit, bitstr))
        return outcomes

    def generate_key(self):
        """
        Generates a shared key of length `self.key_length` (bits).
        Returns: list of ints (0/1) representing the key.
        Also populates alice_bases, bob_bases, alice_bits, bob_bits for inspection.
        """
        self.alice_bases = []
        self.bob_bases = []
        self.alice_bits = []
        self.bob_bits = []

        final_key = []

        # We will generate rounds until final_key has desired length.
        # Create rounds in batches for performance.
        while len(final_key) < self.key_length:
            circuits = []
            batch_meta = []
            # prepare batch of random bases
            for _ in range(self.batch_size):
                a_basis = self.rng.randint(0, 1)  # 0=Z,1=X
                b_basis = self.rng.randint(0, 1)
                circuits.append(self._make_bell_pair_circuit(a_basis, b_basis))
                batch_meta.append((a_basis, b_basis))

            # run the batch and parse outcomes
            outcomes = self._run_batch(circuits)
            for (a_bit, b_bit, _raw), (a_basis, b_basis) in zip(outcomes, batch_meta):
                # append raw data
                self.alice_bases.append(a_basis)
                self.bob_bases.append(b_basis)
                self.alice_bits.append(a_bit)
                self.bob_bits.append(b_bit)
                # if bases match, this round yields a key bit (Alice's bit)
                if a_basis == b_basis:
                    final_key.append(a_bit)
                    # stop early if we have enough
                    if len(final_key) >= self.key_length:
                        break

        # trim to exact requested length
        final_key = final_key[: self.key_length]
        return final_key

    def get_raw_data(self):
        """Return raw collected arrays (might be longer than key_length due to batch)"""
        return {
            "alice_bases": self.alice_bases,
            "bob_bases": self.bob_bases,
            "alice_bits": self.alice_bits,
            "bob_bits": self.bob_bits
        }
