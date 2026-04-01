"""AutoReconAI package setup."""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="autorecon-ai",
    version="0.1.0",
    author="AutoReconAI Contributors",
    description=(
        "AI-powered cybersecurity tool that automates reconnaissance "
        "and suggests relevant exploits based on detected services and versions"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/m4verick0304/autorecon-ai",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "autorecon=autorecon.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
