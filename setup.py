from setuptools import setup, find_packages

setup(
    name="raven",
    version="1.0.0",
    py_modules=["bb_agent"],
    packages=find_packages(),
    install_requires=[
        line.strip() for line in open("requirements.txt").read().splitlines()
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "raven=bb_agent:cli",
        ],
    },
    python_requires=">=3.9",
)
