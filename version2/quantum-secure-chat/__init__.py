"""
Quantum Secure Chat - A quantum-key-distribution secured chat application
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__description__ = "Quantum-secure chat with QKD integration"

from .qkd.bb84 import QKDProtocol
from .qkd.entanglement_qkd import EntanglementQKD
from .qkd.key_composer import BrahmaguptaComposer
from .crypto.aes_manager import QuantumAESManager
from .crypto.key_derivation import RamanujanKDF
from .network.quantum_client import QuantumSecurityClient
from .network.quantum_server import QuantumKeyServer

__all__ = [
    'QKDProtocol',
    'EntanglementQKD', 
    'BrahmaguptaComposer',
    'QuantumAESManager',
    'RamanujanKDF',
    'QuantumSecurityClient',
    'QuantumKeyServer'
]
