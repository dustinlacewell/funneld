#!/usr/bin/env python

from setuptools import setup

setup(name='funneld',
    version='0.1.0',
    description='funnel ssh logins through a single system user',
    author='Dustin Lacewell',
    author_email='dlacewell@gmail.com',
    url='https://github.com/dustinlacewell/funneld',
    install_requires=['twisted', 'pyasn1', 'pycrypto', 'click'],
    py_modules=['funneld'],
    entry_points={
        'console_scripts': [
            'funneld = funneld:main',
        ],
    }
)
