#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging
import os
import re
import shutil
import string
from collections import deque
from os.path import dirname, exists, isdir, isfile, join, relpath, splitext
from subprocess import CalledProcessError, Popen, PIPE


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
    only_parent = False

    def __init__(self, dump, pids):
        """
        Simple constructor for setting base attributes.

        :param dump: VolatilityMemDump instance
        :param pids: list of pids corresponding to the application name in dump
        """
        if not isinstance(pids, list) or any(not x.isdigit() for x in pids):
            raise ValueError("Bad list of PID's (should be list of digits)")
        self.dump = dump
        self.logger = logger
        self.name = self.__class__.__name__
        self.pids = list(set(pids))
        self._filter_pids()
        self.__nopid = []
        if not hasattr(self.__class__, "missing_plugins"):
            self.__class__.missing_plugins = []
    
    def _filter_pids(self):
        """
        Filter out child PID's of processes whose own and parent procnames are
         in self.procnames.
        """
        if self.only_parent:
            for k, v in self.ppids.items():
                ppid, ppname = k
                for pid, pname in v:
                    if ppname == pname:
                        try:
                            self.pids.remove(pid)
                        except ValueError:
                            continue

    def _is_processed(self, pid=None):
        """
        Check if this dumper was already processed for the given PID relying on
         a cache file.
         
        :param pid: PID (if any)
        :return: True if dumper already processed
        """
        if self._update:
            with open(self.dump._cachefile) as f:
                dumpers = f.read().splitlines()[1:]
            name = self.name if pid is None else "{}-{}".format(self.name, pid)
            if name in dumpers:
                self.logger.debug("> Already processed ; nothing to update")
                return True
        return False

    def _makedir(self, *subdirs):
        """
        Compose the dump directory path and create it if it does not exist.

        :param *subdirs: string pieces of the dump directory path
        :return: the dump directory path as a single string
        """
        if any(not isinstance(x, str) for x in subdirs):
            raise ValueError("Bad list of subdirectories (should be a list of "
                             "str)")
        dst = join(self.dump.out_dir, *subdirs)
        if not isdir(dst):
            os.makedirs(dst)
        return dst

    def _run(self, update=False):
        """
        Consecutively execute the public 'run()' method on each PID from the
         pids list.
        
        :param update: update output directory (meaning that collected pieces of
                        information should not be recollected using Volatility
                        commands)
        :return: list of messages (if any) associated to this dumper
        """
        self._update, n = update, self.name
        ok = False
        # applies to system dumpers
        if len(self.pids) == 0:
            if not self._is_processed():
                logger.debug("Dumping information...")
                ok = self.run() is not None
                self.dump._update_cache(dumper=n)
        else:
            for pid in self.pids:
                if not self._is_processed(pid):
                    logger.debug("Dumping for PID {}...".format(pid))
                    self.dump.config.PID = pid
                    ok = self.run() is not None or ok
                    self.dump._update_cache(dumper="{}-{}".format(n, pid))
        return self.messages if ok else []
    
    @property
    def pid(self):
        """
        Dummy shortcut property to self.dump.config.PID.
        """
        _ = self.dump.config.PID
        return _ if _ in self.pids else None
    
    @property
    def ppids(self):
        """
        Dummy shortcut property to self.dump.ppids.
        """
        return self.dump.ppids
    
    def call(self, *args, **kwargs):
        """
        Dummy shortcut to self.dump.call.
        """
        return self.dump.call(*args, **kwargs)

    def carve(self, *types, **kwargs):
        """
        Carve files of given types from the input resource with Foremost.

        :param types: list of extensions to be carved from the resource
        :param clean: remove dump file after processing
        """
        clean = kwargs.pop('clean', False)
        if any(not isinstance(x, str) for x in types):
            raise ValueError("Bad list of types (should be a list of str)")
        if not isinstance(clean, bool):
            raise ValueError("Bad clean variable type (should be bool)")
        fp = self.memdump(verbose=False)
        if clean:
            self.dump._artifacts.append(fp)
        logger.debug("> Carving with Foremost...")
        folder, _ = splitext(fp)
        opt = ["", "-t {}".format(",".join(types))][len(types) > 0]
        cmd = "foremost {} -o {} {}".format(fp, folder, opt)
        logger.debug(">> {}".format(cmd))
        self.shell(cmd)
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
                    logger.info("> {}".format(relpath(fp)))
    
    def commands(self, *cmds, **kwargs):
        """
        Call multiple Volatility commands on the associated dump with the given
         options and save the results.
        """
        fmt = kwargs.pop('fmt', None)
        options = kwargs.pop('options', None)
        save = kwargs.pop('save', True)
        verbose = kwargs.pop('verbose', True)
        header = kwargs.pop('header', 0)
        res = []
        for cmd in cmds:
            if cmd in self.__class__.missing_plugins:
                continue
            # commands can be defined as 'command' or '(command, options)'
            if isinstance(cmd, tuple):
                cmd, opt = cmd
            else:
                opt = None or options
            # handle options separately
            out = self.call(cmd, opt, **kwargs)
            if out is None:
                self.__class__.missing_plugins.append(cmd)
                res.append(None)
                continue
            if save:
                # adapt output format if necessary
                _ = "--output="
                if fmt is None and opt is not None and _ in opt:
                    fmt = filter(lambda x: _ in x, opt.split())[0].split('=')[1]
                else:
                    fmt = "txt"
                dst = self.result(cmd, fmt)
                res.append(self.save(out, dst, verbose, header))
            else:
                res.append(out)
        return tuple(res)
    
    def execute(self, *args, **kwargs):
        """
        Dummy shortcut to self.dump.execute.
        """
        return self.dump.execute(*args, **kwargs)
    
    def has(self, pid):
        """
        Dummy function to verify if input PID matches dumper's associated one.
        """
        return self.pid == pid

    def memdump(self, verbose=True):
        """
        Executes the 'memdump' Volatility command for extracting the related
         process memory.

        :param verbose: display the log message after saving the memory dump
        :return: path to the process memory dump
        """
        if not isinstance(verbose, bool):
            raise ValueError("Bad verbose variable type (should be bool)")
        cmd = 'memdump'
        dst = self.result(cmd, "data")
        if self._update and exists(dst):
            return dst
        out = self.call(cmd, "-p {} --dump-dir {}"
                             .format(self.pid, self.dump.out_dir))
        src = join(self.dump.out_dir, "{}.dmp".format(self.pid))
        # could already exist if previous memdump result was cached
        if not exists(dst):
            shutil.move(src, dst)
        if verbose:
            logger.info("> {}".format(relpath(dst)))
        return dst

    def memsearch(self, split_on_nullbyte=False):
        """
        Executes the 'memdump' Volatility command then parse the collected dump
         against user-defined regular expressions.
        Valid patterns structure:
          self.re_patterns := list(tuples(re_pattern, format, short_descr))
        
        :param split_on_nullbyte: split the matched string on nullbyte and take
                                   only the first part
        """
        if not hasattr(self, "re_patterns"):
            logger.warning("No memory search performed (no pattern found)")
            return
        dump = self.memdump(verbose=False)
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
                self.save(out, self.result('memdump-{}'.format(descr), fmt))
        self.dump._artifacts.append(dump)
    
    def parse(self, output):
        """
        Dummy shortcut to self.dump.OutputParser.

        :param output: Volatility command output as a string
        """
        return self.dump.OutputParser(output)
    
    def result(self, cmd, fmt=None):
        """
        Compose the resource path depending on the executed command and given
         format.
        
        :param cmd: Volatility command name
        :param fmt: output format extension
        :return: relative resource path
        """
        _ = self.name.lower() + "{}-{}{}"
        _ = _.format(["-{}".format(self.pid), ""][self.pid is None], cmd,
                     [".{}".format(fmt), ""][fmt is None])
        return join(self.dump.out_dir, _)

    def run(self):
        """
        Executes the 'memdump' Volatility command for extracting the related
         process memory.
        Public run method to be overridden for the operations to be applied to
         the related application.

        :param verbose: display the log message after saving the memory dump
        """
        raise NotImplementedError("Subclass GenericDumper and override run()")

    def save(self, content, dst, verbose=True, header=0):
        """
        Save a resource to a destination according to naming conventions.

        :param content: content to be saved
        :param dst: relative resource path
        :param verbose: verbose mode
        :param header: number of heading rows to be considered
        :return: path where the file was saved
        """
        content = content or ""
        if not isinstance(content, str):
            raise ValueError("Bad content variable type (should be str)")
        if not isinstance(verbose, bool):
            raise ValueError("Bad verbose variable type (should be bool)")
        content = content.strip()
        if content == "" or len(content.split('\n')) == header:
            logger.debug("Empty content, no resource saved")
            return
        with open(dst, 'wb+') as f:
            f.write(content)
        if verbose:
            logger.info("> {}".format(relpath(dst)))
        return dst
    
    def shell(self, cmd, clean=False):
        """
        Executes an OS command.
        
        :param cmd: command line as text
        :return: stdout, stderr
        """
        cmd = cmd.split()
        try:
            p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            out, err = p.communicate()
            if clean and isfile(cmd[-1]):
                os.remove(cmd[-1])
            return out, err
        except CalledProcessError:
            logger.error("Command '{}' failed".format(cmd))
            return None, None

    def vaddump(self, verbose=True):
        """
        Executes the 'vaddump' Volatility command for extracting the VAD tree
         for a given process.

        :param verbose: display the log message after grabbing the VAD nodes
        :return: path to the VAD dump directory
        """
        if not isinstance(verbose, bool):
            raise ValueError("Bad verbose variable type (should be bool)")
        dst = self._makedir('vad')
        out = self.dump.call('vaddump', "-p {} -D {}".format(self.pid, dst))
        if verbose:
            logger.info("> {}".format(relpath(dst)))
        return dst

    def vadsearch(self, stop=True, include_pattern=False, reduce_text=False):
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
        if not isinstance(stop, bool):
            raise ValueError("Bad stop variable type (should be bool)")
        if not isinstance(include_pattern, bool):
            raise ValueError("Bad include_pattern variable type (should be "
                             "bool)")
        if not isinstance(reduce_text, bool):
            raise ValueError("Bad reduce_text variable type (should be bool)")
        if not hasattr(self, "fmt_patterns"):
            logger.warning("No VAD search performed (no pattern found)")
            return
        dst = self.vaddump(verbose=False)
        for fn in os.listdir(dst):
            with open(join(dst, fn), 'rb') as f:
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
                self.save(out.rstrip('\x00'), self.result('vadnode', fmt))
                if stop:
                    break
        shutil.rmtree(dst)

    def yarascan(self, pattern, verbose=True):
        """
        Executes the 'yarascan' Volatility command for matching a pattern from
         the related process memory.
        
        :param pattern: yara pattern
        :param verbose: display the log message after saving the scan result
        """
        if not isinstance(pattern, str):
            raise ValueError("Bad pattern variable type (should be str)")
        if not isinstance(verbose, bool):
            raise ValueError("Bad verbose variable type (should be bool)")
        cmd = 'yarascan'
        out = self.dump.call(cmd, "-p {} -Y '/{}/'".format(self.pid, pattern))
        if len(out.strip()) == 0:
            return
        i = 0
        dst = self.result(cmd + "-{:0<2}".format(i), "txt")
        while exists(dst):
            i += 1
            dst = self.result(cmd + "-{:0<2}".format(i), "txt")
        with open(dst, 'wb') as f:
            f.write(out)
        if verbose:
            logger.info("> {}".format(relpath(dst)))

    @staticmethod
    def reduce_text(text, alphabet=string.printable, wsize=5, threshold=3):
        """
        Determines start|end bounds based on a window of booleans telling if the
         characters are well in the allowed alphabet with the constraints that
         the first character in the window must be a not-allowed one and the
         number of not-allowed ones in the window is above the threshold
        """
        if not isinstance(text, str):
            raise ValueError("Bad text variable type (should be str)")
        if not isinstance(alphabet, str):
            raise ValueError("Bad alphabet variable type (should be str)")
        if not isinstance(wsize, int):
            raise ValueError("Bad wsize variable type (should be int)")
        if not isinstance(threshold, int):
            raise ValueError("Bad threshold variable type (should be int)")
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
