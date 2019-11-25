# -*- coding: UTF-8 -*-
"""AppmemDumper package information.

"""
import os

__all__ = ["__author__", "__copyright__", "__license__", "__version__"]
__author__    = "Alexandre D'Hondt"
__copyright__ = "A. D'Hondt"
__license__   = "agpl-3.0"
with open(os.path.join(os.path.dirname(__file__), "VERSION.txt")) as f:
    __version__ = f.read().strip()
