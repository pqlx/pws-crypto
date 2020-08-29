from setuptools import setup, find_packages

requirements = [
    "hexdump"
]

setup(name="pws",
        version="1.0",
        install_requires=requirements,
        packages=find_packages())
