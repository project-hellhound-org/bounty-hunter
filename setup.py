from setuptools import setup, find_packages

setup(
    name="hellhound",
    version="12.0.0",
    description="HELLHOUND — Modular Web Offensive Framework",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "beautifulsoup4",
        "colorama",
        "playwright",
        "pyyaml",
        "requests",
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