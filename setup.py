"""
SecureScan - Application Security Scanner
Setup configuration for pip installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="securescan",
    version="1.0.0",
    author="SecureScan Team",
    author_email="security@example.com",
    description="Application Security Scanner - SAST, SCA, and Secrets Detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/securescan",
    project_urls={
        "Bug Tracker": "https://github.com/your-org/securescan/issues",
        "Documentation": "https://github.com/your-org/securescan#readme",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=[
        # No external dependencies required for core functionality
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "securescan=securescan.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
