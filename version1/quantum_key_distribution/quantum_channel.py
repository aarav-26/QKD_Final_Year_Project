class QuantumChannel:
    def __init__(self, error_rate=0.05):
        self.error_rate = error_rate
    
    def transmit(self, qubits):
        # Simulate quantum channel with potential errors
        if random.random() < self.error_rate:
            # Simulate qubit error
            qubits.x(0)  # Flip first qubit as error simulation
        return qubits
