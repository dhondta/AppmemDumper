#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import re
from .template import DumperTemplate


__all__ = [
    "DumpInfo",
    "UserHashes",
]


class DumpInfo(DumperTemplate):
    """
    Dumper of general information about the memory image.
    """
    def run(self):
        """
        Executes a series of informational Volatility commands.
        """
        for cmd in ['crashinfo', 'hibinfo', 'vboxinfo', 'vmwareinfo']:
            self._dump_file(self.dump.call(cmd, silentfail=True), cmd)


class UserHashes(DumperTemplate):
    """
    Dumper of Windows user hashes from the memory image.
    """
    def run(self):
        """
        Executes 'hivelist' and 'hashdump' Volatility commands in order to
         dump user hashes.
        """
        out = self.dump.call("hivelist")
        re1, re2 = re.compile(r'(sam)$', re.I), re.compile(r'(system)$', re.I)
        sam, system = None, None
        for line in out.split('\n'):
            if line.startswith("0x"):
                start, end, hive = line.split(" ", 2)
                if re1.search(hive) is not None:
                    sam = start
                if re2.search(hive) is not None:
                    system = start
        cmd = "hashdump"
        if sam is not None and system is not None:
            out = self.dump.call(cmd, "{} -s {}".format(sam, system))
            self._dump_file(out, cmd)
