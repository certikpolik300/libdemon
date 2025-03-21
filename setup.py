# setup.py

from setuptools import setup, find_packages

setup(
    name="cryptogamax",
    version="3.0",
    description="A Super Strong Cipher for secure encryption and decryption.",
    author="Alfisene Keita",
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'cryptography',  # Ensure this dependency is installed
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
