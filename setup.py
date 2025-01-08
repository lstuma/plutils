from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="admap",
    version="0.1dev",
    license="MIT",
    packages=find_packages(),
    package_data={'': ['*.tcss']},
    install_requires=[
        "utils-pl",
        "ms-active-directory",
        "matplotlib",
        "networkx",
        "pyvis",
        "rich",
        "impacket",
        "textualize",
    ],
    description="Mapper for active directory",
    long_description=long_description,
    entry_points={
        "console_scripts": [
            "map-ad=admap.entry:main",
        ]
    }
)
