from setuptools import setup, find_packages

setup(
    name="tvault",
    version="0.1",
    packages=find_packages(),
    python_requires=">=3.8, <4",
    install_requires=[
        "pycryptodome",
        "inquirer",
    ],
    entry_points={
        "console_scripts": [
            "tvault=tvault.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
)