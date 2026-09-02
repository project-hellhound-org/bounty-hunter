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
        "playwright==1.56.0",
        "pyyaml",
        "requests",
        "rich",
        "prompt_toolkit",
        "pywebview",
        "qtpy",
        "PyQt6",
        "PyQt6-WebEngine",
    ],
    entry_points={
        "console_scripts": [
            # This makes `hellhound` a real system command after install.
            # Points to hellhound/cli.py → main()
            "hellhound = hellhound.cli:main",
        ]
    },
    python_requires=">=3.10",
)