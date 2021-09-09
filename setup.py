from setuptools import find_packages, setup


install_requires = (
    "aiohttp>=3.4.3",
    "aiohttp-security>=0.4.0",
    "python-jose>=3.0.1",
)

setup(
    name="neuro-auth-client",
    use_scm_version={
        "root": "..",
        "relative_to": __file__,
        "git_describe_command": "git describe --dirty --tags --long --match v*.*.*",
    },
    url="https://github.com/neuromation/platform-auth",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=install_requires,
    setup_requires=["setuptools_scm"],
    zip_safe=False,
)
