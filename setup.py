from setuptools import setup, find_packages

setup(
    name="hellhound",
    version="12.7.0",
    description="HELLHOUND — Autonomous AI Bug Bounty Reconnaissance & Triage Framework",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "beautifulsoup4",
        "click",
        "colorama",
        "cryptography",
        "lxml",
        "playwright==1.56.0",
        "pyyaml",
        "requests",
        "rich",
        "prompt_toolkit",
        "textual>=0.80",
    ],
    entry_points={
        "console_scripts": [
            # `beast` is the primary command (the tool's nickname); `hellhound`
            # stays as a back-compat alias. Both point to hellhound/cli.py → main().
            "beast = hellhound.cli:main",
            "hellhound = hellhound.cli:main",
        ]
    },
    python_requires=">=3.10",
)