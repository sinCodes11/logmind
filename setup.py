"""Setup script for LogMind."""

from setuptools import setup, find_packages

setup(
    name="logmind",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.1.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.0",
        "structlog>=24.0.0",
        "sqlalchemy>=2.0.0",
        "psycopg2-binary>=2.9.0",
        "redis>=5.0.0",
        "anthropic>=0.18.0",
        "requests>=2.31.0",
        "aiofiles>=23.0.0",
    ],
    extras_require={
        "oci": ["oci>=2.100.0"],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "logmind=logmind.cli:main",
        ],
    },
    python_requires=">=3.11",
    author="Daniel Gregg Jr",
    description="LLM-Powered Security Log Analyzer",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
    ],
)
