#!/usr/bin/env python3
"""Setup configuration for proof-of-work package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the long description from README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="proof-of-work",
    version="1.0.0",
    description="High-performance Proof-of-Work library with support for 34 hash algorithms",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="QudsLab",
    author_email="contact@qudslab.com",
    url="https://github.com/QudsLab/Proof-of-work",
    license="MIT",
    packages=find_packages(where="python"),
    package_dir={"": "python"},
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="proof-of-work crypto hash blake2 sha3 md5 ripemd",
    project_urls={
        "Bug Reports": "https://github.com/QudsLab/Proof-of-work/issues",
        "Documentation": "https://github.com/QudsLab/Proof-of-work#readme",
        "Source Code": "https://github.com/QudsLab/Proof-of-work",
    },
    include_package_data=True,
)
