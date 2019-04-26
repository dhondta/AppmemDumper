#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import re

from .template import DumperTemplate


__all__ = [
    "Clipboard",
    "CriticalProcessesInfo",
    "DumpInfo",
    "Mimikatz",
    "UserHashes",
]


class Clipboard(DumperTemplate):
    """
    Dumper for collecting the content of the clipboard.
    """
    def run(self):
        out = self.dump.call("clipboard", failmode="warn")
        if len(out.split('\n')) > 3:
            self._dump_file(out, "content")
        else:
            logger.debug("Empty content, no resource saved")


class CriticalProcessesInfo(DumperTemplate):
    """
    Dumper for checking critical processes.
    """
    def run(self):
        self.dump.config.PID = None
        kw = {'options': "--output=greptext", 'failmode': "silent"}
        pslist, pstree, psscan, psxview = \
            [self._dump_file(self.dump.call(cmd, **kw), cmd) \
             for cmd in ['pslist', 'pstree', 'psscan', 'psxview']]
        info = ""
        # check for single instance of lsass.exe and services.exe
        for ps in ["lsass.exe", "services.exe"]:
            instances = []
            with open(psscan) as f:
                for l in f:
                    l = l.split("|")
                    if ps in l:
                        instances += [(l[3], l[4])]  # PID, PPID
            pids = list(map(lambda x: x[0], instances))
            with open(psxview) as f:
                for l in f:
                    l = l.split("|")
                    pid = l[3]
                    if ps in l and pid not in pids:
                        instances += [(pid, "N/A")]  # PID, PPID
            if len(instances) > 1:
                info += "Multiple instances of {} found".format(ps)
                for pid, ppid in sorted(instances, key=lambda x: int(x[0])):
                    info += "\n{} (parent: {})".format(pid, ppid)
                self._dump_file(info, "multiple-{}".format(ps.split(".", 1)[0]))


class DumpInfo(DumperTemplate):
    """
    Dumper of general information about the memory image.
    """
    def run(self):
        """
        Executes a series of informational Volatility commands.
        """
        for cmd in ['crashinfo', 'hibinfo', 'vboxinfo', 'vmwareinfo']:
            self._dump_file(self.dump.call(cmd, failmode="silent"), cmd)


class Mimikatz(DumperTemplate):
    """
    Dumper for collecting user passwords present in memory.
    """
    def run(self):
        cmd = "mimikatz"
        self._dump_file(self.dump.call(cmd, failmode="warn"), cmd)


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
