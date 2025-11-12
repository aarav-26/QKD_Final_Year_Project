from setuptools import setup, find_packages

setup(
    name="quantum-secure-chat",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "qiskit>=1.0.0",
        "qiskit-aer>=0.12.0", 
        "cryptography>=3.4.0",
        "flask>=2.0.0",
        "flask-cors>=3.0.0",
        "requests>=2.25.0"
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="Quantum-secure chat application with QKD integration",
    long_description=open('README.md').read() if os.path.exists('README.md') else "",
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications :: Chat"
    ],
    keywords="quantum cryptography chat security qkd",
    url="https://github.com/yourusername/quantum-secure-chat",
)
