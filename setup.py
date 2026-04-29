from setuptools import setup, find_packages

setup(
    name="hellhound",
    version="12.5.1",
    description="HELLHOUND — Modular Web Offensive Framework",
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