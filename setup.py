#!/usr/bin/env python

# Copyright 2011 Andrew Ryrie (amr66)

from distutils.core import setup

setup(name='django-ucamwebauth',
      description='A Django authentication backend for Ucam-WebAuth / Raven',
      long_description=open('README.md').read(),
      url='https://git.csx.cam.ac.uk/x/ucs/raven/django-ucamwebauth.git',
      version='1.0',
      license='MIT',
      author='Andrew Ryrie',
      author_email='smb314159@gmail.com',
      maintainer='University Information Services, University of Cambridge',
      maintainer_email='raven-support@cam.ac.uk',
      packages=['ucamwebauth'],
      install_requires=['pyOpenSSL'],
      )
