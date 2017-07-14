#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages

setup(
    name='django-ucamwebauth',
    description='A Django authentication backend for Ucam-WebAuth a.k.a. Raven',
    long_description=open('README.rst').read(),
    url='https://git.csx.cam.ac.uk/x/ucs/raven/django-ucamwebauth.git',
    # When changing this version number, remember to update
    # django-ucamwebauth.spec and debian/changelog.
    version='1.4.3',
    license='MIT',
    author='Information Systems Group, University Information Services, University of Cambridge',
    author_email='raven-support@cam.ac.uk',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['pyOpenSSL'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)
