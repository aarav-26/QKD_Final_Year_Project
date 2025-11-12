from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import random
import numpy as np

class QKDProtocol:
    def __init__(self, key_length=256):
        self.key_length = key_length
        self.backend = AerSimulator()
        self.rng = random.SystemRandom()
        self.alice_bits = []
        self.alice_bases = []
        self.bob_bases = []
        self.bob_bits = []
    
    def generate_bits_and_bases(self):
        bits = self.generate_random_bits(self.key_length)
        bases = self.generate_random_bits(self.key_length)
        #print(f"bits :{bits}")
        #print(f"bases :{bases}")
        return bases, bits

    def generate_random_bits(self, length):
        return [self.rng.randint(0, 1) for _ in range(length)]
    
    def encode_qubits(self, bits, bases):
        circuit = QuantumCircuit(len(bits), len(bits))
        for i, (bit, base) in enumerate(zip(bits, bases)):
            if bit == 1:
                circuit.x(i)
            if base == 1:
                circuit.h(i)
        return circuit
    
    def measure_qubits(self, circuit, bases):
        for i, base in enumerate(bases):
            if base == 1:
                circuit.h(i)
        circuit.measure(range(len(bases)), range(len(bases)))
        return circuit
    
    def generate_key(self):
        self.alice_bits = self.generate_random_bits(self.key_length)
        self.alice_bases = self.generate_random_bits(self.key_length)
        self.bob_bases = self.generate_random_bits(self.key_length)
        
        qc = self.encode_qubits(self.alice_bits, self.alice_bases)
        qc = self.measure_qubits(qc, self.bob_bases)
        
        job = self.backend.run(qc, shots=1)
        result = job.result()
        counts = result.get_counts(qc)
        
        bob_bits_str = list(counts.keys())[0][::-1]
        self.bob_bits = [int(bit) for bit in bob_bits_str]
        
        matching_bases = [i for i in range(self.key_length) if self.alice_bases[i] == self.bob_bases[i]]
        final_key = [int(self.alice_bits[i]) for i in matching_bases]
        
        return final_key

    def get_raw_data(self):
        return {
            "alice_bits": self.alice_bits,
            "alice_bases": self.alice_bases,
            "bob_bases": self.bob_bases,
            "bob_bits": self.bob_bits
        }
