#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging
import os
import re
import shutil
import string
from collections import deque
from os.path import exists, isdir, isfile, join, relpath, splitext
from subprocess import Popen, PIPE


__all__ = ["DumperTemplate"]
logger = logging.getLogger("main")


class DumperTemplate(object):
    """
    Dumper template class for handling base operations on the memory dump for
     handled applications. It can execute Volatility commands using the attached
     VolatilityMemDump instance and carve files using Foremost.
    """
    _predef_messages = [
        "Raw data (.data files) requires manual handling ;\n"
        "Follow this procedure:\n"
        " 1. Open the collected resources with Gimp\n"
        " 2. Set the width and height to the expected screen resolution\n"
        " 3. Set another color palette than 'RVB'\n"
        "Restart this procedure by setting other parameters for width|height"
        "|palette.",
        "VAD objects (collected with 'vaddump' require further research ;\n"
        "If you know some keywords that could match text elements, you can grep"
        " the .dmp objects.",
    ]
    messages = []
    procnames = None  # by default, the GenericDumper does not correspond to
                      # any particular process name, meaning that a dumper
                      # inheriting this class without redefining procnames will
                      # be processed regardless of the process list

    def __init__(self, dump, name, pids):
        """
        Simple constructor for setting base attributes.

        :param dump: VolatilityMemDump instance
        :param name: application name
        :param pids: list of pids corresponding to the application name in dump
        """
        assert isinstance(name, str)
        assert isinstance(pids, list) and all(x.isdigit() for x in pids)
        self.dump = dump
        self.pids = pids
        self._resname = lambda p, c, f=None: (name.lower() + "{}-{}{}") \
                                .format(["-{}".format(p), ""][p is None], c, \
                                        [".{}".format(f), ""][f is None])
        self.__nopid = []

    def _dump_dir(self, *subdirs):
        """
        Compose the dump directory path and create it if it does not exist.

        :param *subdirs: string pieces of the dump directory path
        :return: the dump directory path as a single string
        """
        assert all(isinstance(x, str) for x in subdirs)
        d = join(self.dump.out_dir, *subdirs)
        if not isdir(d):
            os.makedirs(d)
        return d

    def _dump_file(self, content, cmd, fmt="txt", verbose=True):
        """
        Save a resource to a destination respecting naming conventions.

        :param res: resource file to be saved
        :param pid: PID from which the resource was extracted
        :param cmd: Volatility command used to extract the resource
        :param fmt: extension of the destination resource
        """
        content = content or ""
        assert isinstance(content, str)
        assert isinstance(cmd, str)
        assert isinstance(fmt, str)
        assert isinstance(verbose, bool)
        if content.strip() == "":
            logger.debug("Empty content, no resource saved")
            return
        d = join(self.dump.out_dir,
                 self._resname(self.dump.config.PID, cmd, fmt))
        with open(d, 'wb') as f:
            f.write(content)
        if verbose:
            logger.info("> {}".format(relpath(d)))
        return d

    def _memdump(self, verbose=True):
        """
        Executes the 'memdump' Volatility command for extracting the related
         process memory.

        :param verbose: display the log message after saving the memory dump
        :return: path to the process memory dump
        """
        assert isinstance(verbose, bool)
        cmd, pid = 'memdump', self.dump.config.PID
        out = self.dump.call(cmd,
            "-p {} --dump-dir {}".format(pid, self.dump.out_dir))
        src = join(self.dump.out_dir, "{}.dmp".format(pid))
        dst = join(self.dump.out_dir, self._resname(pid, cmd, "data"))
        shutil.move(src, dst)
        if verbose:
            logger.info("> {}".format(dst))
        return dst

    def _memsearch(self, split_on_nullbyte=False):
        """
        Executes the 'memdump' Volatility command then parse the collected dump
         against used-defined regular expressions.
        Valid patterns structure:
          self.re_patterns := list(tuples(re_pattern, format, short_descr))
        
        :param split_on_nullbyte: split the matched string on nullbyte and take
                                   only the first part
        """
        if not hasattr(self, "re_patterns"):
            logger.warning("No memory search performed (no pattern found)")
            return
        dump = self._memdump(verbose=False)
        with open(dump) as f:
            content = f.read()
        for pattern, fmt, descr in self.re_patterns:
            r = re.compile(pattern, re.M + re.S)
            out = r.search(content)
            if out is not None:
                out = out.group()
                #FIXME: split on nullbyte for each occurrence then join all
                if split_on_nullbyte:
                    out = out.split('\x00', 1)[0]
                self._dump_file(out, 'memdump-{}'.format(descr), fmt)
        os.remove(dump)

    def _run(self):
        """
        Consecutively execute the public 'run()' method on each PID from the
         pids list.
        """
        if len(self.pids) == 0:
            logger.debug("Dumping information...")
            self.run()
        else:
            for pid in self.pids:
                logger.debug("Dumping for PID {}...".format(pid))
                self.dump.config.PID = pid
                self.run()
        return self.messages

    def _vaddump(self, verbose=True):
        """
        Executes the 'vaddump' Volatility command for extracting the VAD tree
         for a given process.

        :param verbose: display the log message after grabbing the VAD nodes
        :return: path to the VAD dump directory
        """
        assert isinstance(verbose, bool)
        dump_dir = self._dump_dir('vad')
        out = self.dump.call('vaddump', "-p {} -D {}" \
                             .format(self.dump.config.PID, dump_dir))
        if verbose:
            logger.info("> {}".format(dump_dir))
        return dump_dir

    def _vadsearch(self, stop=True, include_pattern=False, reduce_text=False):
        """
        Executes the 'vaddump' Volatility command then parse the collected VAD
         nodes against used-defined patterns for collecting resources.
        Valid patterns structure:
          self.fmt_patterns := list(tuples(start_pattern, end_pattern, format))
        
        :param stop: stop after the first resource matching the patterns
        :param include_pattern: include the found pattern when saving resource
        :param reduce_text: use GenericDumper to reduce the output (makes sense
                            if the output is text)
        """
        assert isinstance(stop, bool)
        assert isinstance(include_pattern, bool)
        assert isinstance(reduce_text, bool)
        if not hasattr(self, "fmt_patterns"):
            logger.warning("No VAD search performed (no pattern found)")
            return
        dump_dir = self._vaddump(verbose=False)
        for fn in os.listdir(dump_dir):
            with open(join(dump_dir, fn), 'rb') as f:
                node = f.read()
            # choose the first start matching pattern in the provided list of
            #  format patterns
            found = False
            for start, end, fmt in self.fmt_patterns:
                try:
                    out = ["", start][include_pattern] + node.split(start, 1)[1]
                    out = out.split(end, 1)[0] + ["", end][include_pattern]
                    found = True
                    break
                except:
                    continue
            if found:
                if reduce_text:
                    out = GenericDumper.reduce_text(out)
                self._dump_file(out.rstrip('\x00'), 'vadnode', fmt)
                if stop:
                    break
        shutil.rmtree(dump_dir)

    def _yarascan(self, pattern, verbose=True):
        """
        Executes the 'yarascan' Volatility command for matching a pattern from
         the related process memory.
        
        :param pattern: yara pattern
        :param verbose: display the log message after saving the scan result
        """
        assert isinstance(pattern, str)
        assert isinstance(verbose, bool)
        cmd, pid = 'yarascan', self.dump.config.PID
        out = self.dump.call(cmd, "-p {} -Y '/{}/'".format(pid, pattern))
        print(out)
        if len(out.strip()) == 0:
            return
        i = 0
        dst = join(self.dump.out_dir,
                   self._resname(pid, cmd + "-{:0<2}".format(i), "txt"))
        while exists(dst):
            i += 1
            dst = join(self.dump.out_dir,
                       self._resname(pid, cmd + "-{:0<2}".format(i), "txt"))
        with open(dst, 'wb') as f:
            f.write(out)
        if verbose:
            logger.info("> {}".format(dst))

    def carve(self, filepath, types=(), clean=False):
        """
        Carve files of given types from the input resource with Foremost.

        :param filepath: file path of the resource to be carved
        :param types: list of extensions to be carved from the resource
        """
        assert isfile(filepath)
        assert (isinstance(types, tuple) or isinstance(types, list)) and \
               all(isinstance(x, str) for x in types)
        assert isinstance(clean, bool)
        logger.debug("> Carving with Foremost...")
        folder, _ = splitext(filepath)
        opt = ["", "-t {}".format(",".join(types))][len(types) > 0]
        cmd = "foremost {} -o {} {}".format(filepath, folder, opt)
        logger.debug(">> {}".format(cmd))
        p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        with open(join(folder, "audit.txt")) as f:
            disp = False
            for line in f.readlines():
                line = line.strip()
                if "Finish:" in line:
                    break
                if all([x in line for x in ("Num", "Name", "Size", "Comment")]):
                    disp = True
                if disp and len(line) > 0 and ":" in line:
                    fn = line.split(":", 1)[1].strip().split()[0]
                    _, ext = splitext(fn)
                    fp = join(folder, ext[1:], fn)
                    logger.info("> {}".format(fp))
        if clean:
            os.remove(filepath)

    def run(self):
        """
        Executes the 'memdump' Volatility command for extracting the related
         process memory.
        Public run method to be overridden for the operations to be applied to
         the related application.

        :param verbose: display the log message after saving the memory dump
        """
        raise NotImplementedError("Subclass GenericDumper and override run()")

    @staticmethod
    def reduce_text(text, alphabet=string.printable, wsize=5, threshold=3):
        """
        Determines start|end bounds based on a window of booleans telling if the
         characters are well in the allowed alphabet with the constraints that
         the first character in the window must be a not-allowed one and the
         number of not-allowed ones in the window is above the threshold
        """
        assert isinstance(text, str)
        assert isinstance(alphabet, str)
        assert isinstance(wsize, int)
        assert isinstance(threshold, int)
        # NB: the text is in UTF-16 little-endian and can simply be retrieved
        #     by removing the nullbytes after each normal character
        text = text.replace('\x00', '').replace('\r\n', '\n')
        halflen = len(text) / 2
        bounds = [halflen, len(text) - halflen - 1]
        for i, t in enumerate([text[:halflen][::-1], text[halflen:]]):
            w = deque(maxlen=wsize)
            bound_adapted = False
            # slide along the text to adapt the bound
            for k, c in enumerate(t):
                w.append(c not in alphabet)
                if w[0] and sum(w) >= threshold:
                    bounds[i] = k - len(w) + 1
                    bound_adapted = True
                    break
            # handle the window of the text tail if bound not adapted yet
            if not bound_adapted:
                for j in range(wsize - 1):
                    new_th = int(round(float(threshold) / wsize * len(w)))
                    if w.popleft() and sum(w) >= new_th:
                        bounds[i] = k - len(w)
                        break
        return text[halflen-bounds[0]:halflen+bounds[1]]
