#!/usr/bin/env python

# Copyright 2011 Andrew Ryrie (amr66)

from distutils.core import setup

setup(name='pyroven',
      description='A Django authentication backend for Ucam-WebAuth / Raven',
      long_description=open('README.md').read(),
      url='https://github.com/pyroven/django-pyroven',
      version='0.9',
      license='MIT',
      packages=['pyroven'],
      )
