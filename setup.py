#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from os.path import abspath, dirname, join
from setuptools import setup, find_packages
try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements


currdir = abspath(dirname(__file__))
with open(join(currdir, 'README.md')) as f:
    long_descr = f.read()

requirements = parse_requirements("requirements.txt", session=False)
setup(
  name = "appmemdumper",
  packages = find_packages(),
  author = "Alexandre D\'Hondt",
  author_email = "alexandre.dhondt@gmail.com",
  url = "https://github.com/dhondta/AppmemDumper",
  license = "AGPLv3",
  version = "2.1.5",
  description = "This tool allows to collect various forensics artifacts in "
                "Windows memory dumps using Volatility and Foremost for common "
                "Windows applications.",
  long_description=long_descr,
  long_description_content_type='text/markdown',
  scripts = ["app-mem-dumper"],
  keywords = ["forensics", "volatility", "foremost", "artifacts", "windows", "applications"],
  classifiers = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'Intended Audience :: Information Technology',
    'Intended Audience :: End Users/Desktop',
    'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
  ],
  install_requires=[str(r.req) for r in requirements],
  python_requires = '>=2.7,<3',
)
