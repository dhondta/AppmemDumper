#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import re
import shutil
from os.path import join, relpath

from .template import DumperTemplate


__all__ = [
    "Autoruns",
    "Clipboard",
    "CommandLines",
    "CriticalProcessesInfo",
    "Devices",
    "DumpInfo",
    "FilesList",
    "Kernel",
    "LsaSecrets",
    "Malfind",
    "Mimikatz",
    "NetworkConnections",
    "ProcessesInfo",
    "Registry",
    "Timeline",
    "UserActivities",
    "UserHashes",
]


class Autoruns(DumperTemplate):
    """
    Dumper for mapping AutoStart Extensibility Points to running processes.
    """
    def run(self):
        self.commands('autoruns')


class Clipboard(DumperTemplate):
    """
    Dumper for collecting the content of the clipboard.
    """
    messages = ["Something was found in the clipboard ; you should take a look "
                "at it, there could be some passwords..."]
    
    def run(self):
        out = self.call("clipboard", failmode="warn").split('\n')
        # we want to know if column "Data" has a value, so take its start index
        n = out[0].index("Data")
        new = out[:2]
        for i in range(2, len(out)):
            # now, take this line only if column "Data" has a value
            if len(out[i].rstrip()) > n:
                new.append(out[i])
        r = self.result("content", "txt")
        return self.save('\n'.join(new), r, header=2)


class CommandLines(DumperTemplate):
    """
    Dumper for collecting last commands ran.
    """
    def run(self):
        self.commands('cmdscan', 'consoles', 'cmdline')


class CriticalProcessesInfo(DumperTemplate):
    """
    Dumper for checking critical processes.
    """
    # TODO: check that lsass.exe is only one instance AND its parent is
    #        wininit.exe (Vista+) or winlogon.exe (XP-)
    def run(self):
        psscan, psxview = self.commands('psscan', 'psxview', save=False,
                                        options="--output=greptext")
        info = ""
        # check for single instance of lsass.exe and services.exe
        for ps in ["lsass.exe", "services.exe"]:
            name = ps.split(".", 1)[0]
            instances = []
            for l in psscan.strip().split('\n'):
                l = l.split("|")
                if ps in l:
                    instances += [(l[3], l[4])]  # PID, PPID
            pids = list(map(lambda x: x[0], instances))
            for l in psxview.strip().split('\n'):
                l = l.split("|")
                pid = l[3]
                if ps in l and pid not in pids:
                    instances += [(pid, "N/A")]  # PID, PPID
            if len(instances) > 1:
                info += "Multiple instances of {} found".format(ps)
                for pid, ppid in sorted(instances, key=lambda x: int(x[0])):
                    info += "\n{} (parent: {})".format(pid, ppid)
                self.save(info, self.result("multiple-{}".format(name)))


class Devices(DumperTemplate):
    """
    Dumper for listing device drivers.
    """
    def run(self):
        self.commands('devicetree')


class DumpInfo(DumperTemplate):
    """
    Dumper of general information about the memory image.
    """
    def run(self):
        """
        Executes a series of informational Volatility commands.
        """
        self.commands('crashinfo', 'hibinfo', 'vboxinfo', 'vmwareinfo')


class FilesList(DumperTemplate):
    """
    Dumper for the list of file objects.
    """
    def run(self):
        self.commands('filescan')


class Kernel(DumperTemplate):
    """
    Dumper for getting kernel-related information.
    """
    def run(self):
        self.commands('callbacks', 'timers')


class LsaSecrets(DumperTemplate):
    """
    Dumper for collecting user activity artifacts.
    """
    def run(self):
        """
        Executes 'hivelist' and 'lsadump' Volatility commands in order to dump
         LSA secrets.
        """
        sec, sys = None, None
        for line in self.call("hivelist").split('\n'):
            if line.startswith("0x"):
                start, end, hive = line.split(" ", 2)
                if re.search(r'(security)$', hive, re.I) is not None:
                    sec = start
                if re.search(r'(system)$', hive, re.I) is not None:
                    sys = start
        if sec is not None and sys is not None:
            self.commands("lsadump", options="-y {} -s {}".format(sys, sec))


class Malfind(DumperTemplate):
    """
    Dumper for finding hidden or injected code/DLLs in user mode memory,
     unlinked DLLs and detecting hollowing techniques.
    """
    def run(self):
        if self.commands('malfinddeep', failmode="warn")[0] is None:
            self.commands('malfind')
        self.commands('ldrmodules', 'hollowfind')


class Mimikatz(DumperTemplate):
    """
    Dumper for collecting user passwords present in memory.
    """
    def run(self):
        self.commands('mimikatz', header=2, failmode="warn")


class NetworkConnections(DumperTemplate):
    """
    Dumper for scanning TCP connections and sockets.
    """
    def run(self):
        self.commands('netscan', 'connscan', 'sockscan')


class ProcessesInfo(DumperTemplate):
    """
    Dumper for listing processes.
    """
    def run(self):
        self.commands('pslist', 'pstree', 'psscan', 'psxview')


class Registry(DumperTemplate):
    """
    Dumper for extracting all available registry hives.
    """
    def run(self):
        d = self.dump.out_dir
        tmp = os.path.join(d, ".registry")
        try:
            os.makedirs(tmp)
        except OSError:
            pass
        self.commands('dumpregistry', options="--dump-dir {}".format(tmp))
        for fn in os.listdir(tmp):
            fp = join(tmp, fn)
            with open(fp, 'rb') as f:
                _ = f.read().strip('\x00')
            if len(_) > 0:
                t = fn.split('.')
                nf = "{}.{}".format('-'.join(t[:-1]), t[-1])
                np = join(d, nf)
                with open(np, 'wb') as f:
                    f.write(_)
                self.logger.info("> {}".format(relpath(np)))
        shutil.rmtree(tmp)


class Timeline(DumperTemplate):
    """
    Dumper for creating a timeline from various artifacts in memory.
    """
    def run(self):
        out = '\n'.join(self.commands('timeliner',
                                      ('mftparser', "-C --output=body"),
                                      'shellbags', save=False,
                                      options="--output=body", failmode="warn"))
        tmp = self.save(out, self.result("temp"), verbose=False)
        out, _ = self.shell("mactime -d -b {}".format(tmp), True)
        self.save(out, self.result("mactimes", "csv"))


class UserActivities(DumperTemplate):
    """
    Dumper for collecting user activity artifacts.
    """
    def run(self):
        self.commands('userassist')


class UserHashes(DumperTemplate):
    """
    Dumper of Windows user hashes from the memory image.
    """
    def run(self):
        """
        Executes 'hivelist' and 'hashdump' Volatility commands in order to dump
         user hashes.
        """
        sam, sys = None, None
        for line in self.call("hivelist").split('\n'):
            if line.startswith("0x"):
                start, end, hive = line.split(" ", 2)
                if re.search(r'(sam)$', hive, re.I) is not None:
                    sam = start
                if re.search(r'(system)$', hive, re.I) is not None:
                    sys = start
        if sam is not None and sys is not None:
            self.commands("hashdump", options="{} -s {}".format(sam, sys))
