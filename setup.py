from setuptools import setup, find_packages

setup(
    name="hellhound",
    version="1.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "hellhound": [
            "config.yaml",
            "scripts/*.sh",
            "wordlists/*.txt",
            "web/templates/*.html"
        ]
    },
    install_requires=[
        "click",
        "flask",
        "flask-socketio",
        "requests",
        "pyyaml"
    ],
    entry_points={
        "console_scripts": [
            "hellhound=hellhound.cli:main"
        ]
    },
)
