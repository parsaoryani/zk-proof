from setuptools import setup, find_packages

setup(
    name="regulated-zk-mixer",
    version="0.1.0",
    description="Regulated ZK-Mixer: Combining Zerocash & Morales et al. Concepts",
    author="ZK-Mixer Team",
    author_email="team@zk-mixer.dev",
    url="https://github.com/zk-project/regulated-zk-mixer",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography>=40.0.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "sqlalchemy>=2.0.0",
        "alembic>=1.12.0",
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
        "api": [
            "fastapi>=0.95.0",
            "uvicorn>=0.21.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
