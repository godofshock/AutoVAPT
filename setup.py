from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="autovapt",
    version="1.0.0",
    author="Aagnik",
    author_email="your@email.com",
    description="Automated Vulnerability Assessment & Penetration Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/AutoVAPT",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "autovapt=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    keywords="vapt penetration-testing vulnerability-scanner cybersecurity",
)
