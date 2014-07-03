#!/usr/bin/env python

from distutils.core import setup

setup(
    name='django-ucamwebauth',
    description='A Django authentication backend for Ucam-WebAuth a.k.a. Raven',
    long_description=open('README').read(),
    url='https://git.csx.cam.ac.uk/x/ucs/raven/django-ucamwebauth.git',
    version='1.0',
    license='MIT',
    author='Information Systems Group, University Information Services, University of Cambridge',
    author_email='raven-support@cam.ac.uk',
    maintainer='Information Systems Group, University Information Services, University of Cambridge',
    maintainer_email='raven-support@cam.ac.uk',
    packages=['ucamwebauth'],
    install_requires=['pyOpenSSL'],
)
