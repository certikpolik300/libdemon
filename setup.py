# setup.py

from setuptools import setup, find_packages

setup(
    name="cryptogalyrex",
    version="1.0",
    description="...",
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
