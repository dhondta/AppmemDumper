#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from .application import *
from .system import *
from .template import *

from .application import __all__ as apps
from .system import __all__ as syst


APPDUMPERS = sorted(apps)
SYSDUMPERS = sorted(syst)
__all__ = ["APPDUMPERS", "SYSDUMPERS"] + APPDUMPERS + SYSDUMPERS
