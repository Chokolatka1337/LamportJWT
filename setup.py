from setuptools import setup, find_packages

setup(
    name='LamportJWT',
    version='0.1',
    packages=find_packages(include=['lamport_jwt', 'lamport_jwt.*']),
    install_requires=[]
)
