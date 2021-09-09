from setuptools import find_packages, setup


install_requires = (
    "aiohttp>=3.4.3",
    "aiohttp-security>=0.4.0",
    "python-jose>=3.0.1",
)

setup(
    name="neuro-auth-client",
    use_scm_version=True,
    url="https://github.com/neuro-inc/neuro-auth-client",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=install_requires,
    setup_requires=["setuptools_scm"],
    zip_safe=False,
)
