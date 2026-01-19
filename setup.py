from setuptools import setup, find_packages

setup(
    name="hellhound-pentest",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'hellhound=hellhound.cli:main',
        ],
    },
)
