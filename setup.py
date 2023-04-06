#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

extras_require = {
    "test": [  # `test` GitHub Action jobs uses this
        "pytest>=6.0",  # Core testing package
        "pytest-xdist",  # multi-process runner
        "pytest-cov",  # Coverage analyzer plugin
        "hypothesis>=6.2.0,<7.0",  # Strategy-based fuzzer
    ],
    "lint": [
        "black>=23.1.0,<24",  # Auto-formatter and linter
        "mypy>=0.991",  # Static type analyzer
        "types-setuptools",  # Needed for mypy type shed
        "flake8>=6.0.0,<7",  # Style linter
        "isort>=5.10.1,<6",  # Import sorting linter
    ],
    "release": [  # `release` GitHub Action job uses this
        "setuptools",  # Installation tool
        "wheel",  # Packaging tool
        "twine==3.8.0",  # Package upload tool
    ],
    "dev": [
        "commitizen",  # Manage commits and publishing releases
        "pre-commit",  # Ensure that linters are run prior to commiting
        "pytest-watch",  # `ptw` test watcher/runner
        "IPython",  # Console for interacting
        "ipdb",  # Debugger (Must use `export PYTHONBREAKPOINT=ipdb.set_trace`)
    ],
}

# NOTE: `pip install -e .[dev]` to install package
extras_require["dev"] = (
    extras_require["test"]
    + extras_require["lint"]
    + extras_require["release"]
    + extras_require["dev"]
)

with open("./README.md") as readme:
    long_description = readme.read()


setup(
    name="ape-safe",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    description="""ape-safe: Gnosis Safe account plugin for Ape""",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="banteg.",
    author_email="banteeg@gmail.com",
    url="https://github.com/banteg/ape-safe",
    include_package_data=True,
    install_requires=[
        "eth-ape>=0.6.7,<0.7.0",
        "eip712>=0.2.0,<0.3.0",
    ],
    entry_points={
        "ape_cli_subcommands": [
            "ape_safe=ape_safe._cli:cli",
        ],
    },
    python_requires=">=3.8,<3.11",
    extras_require=extras_require,
    py_modules=["ape_safe"],
    license="Apache-2.0",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={"ape_safe": ["py.typed"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
