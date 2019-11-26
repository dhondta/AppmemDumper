#!/usr/bin/python
# -*- coding: UTF-8 -*-
import logging
import os
import shlex
import shutil
import StringIO
import sys
from copy import deepcopy
from os.path import abspath, dirname, exists, expanduser, isdir, isfile, join
from subprocess import check_output, CalledProcessError, PIPE, Popen

import volatility.addrspace as addrspace
import volatility.conf as conf
import volatility.commands as commands
import volatility.constants as constants
import volatility.debug as debug
import volatility.obj as obj
import volatility.registry as registry
import volatility.utils as utils

from .dumpers import *

try:
    Popen(["foremost", "-h"], stdout=PIPE, stderr=PIPE)
except OSError:
    print("Missing dependencies, please run 'sudo apt-get install foremost'")
    sys.exit(1)


__all__ = ["APPDUMPERS", "SYSDUMPERS", "VolatilityMemDump"]
CMD = 'volatility {opt} {cmd}'
logger = logging.getLogger("main")


is_memdump = lambda x: isinstance(x, VolatilityMemDump)


class VolatilityAppDumper(object):
    """
    Volatility application dumper "relay" class for choosing the right
     application dumper based on the process name. It is called by
     VolatilityMemDump at process list creation to attach the desired dumpers.
     It instantiates a child class of GenericDumper adapted to the given
     application name.
    """
    def __init__(self, dump, pname=None):
        """
        Attaches the parent memory dump file and instantiates the right child
         class of GenericDumper adapted for the input application name.

        :param dump: VolatilityMemDump instance
        :param pname: application process name
        """
        if not isinstance(dump, VolatilityMemDump):
            raise ValueError("Not a VolatilityMemDump instance")
        if pname is not None and not isinstance(pname, str):
            raise ValueError("Bad process name variable type (should be str)")
        # first, find if PID's exist when a process name is given
        pids = []
        if pname is not None:
            for p in dump.processes:
                if pname == str(p.ImageFileName).lower():
                    pids.append(str(p.UniqueProcessId))
            if len(pids) == 0:
                logger.error("No PID found for '{}'".format(pname))
                return
        # second, find the right application dumper for the given process name
        #  and attach the dumper to the memory dump if a dumper is found and if
        #  the related application is handled
        # if no process name was given and there exists a system dumper (that
        #  has no list of process names), create a dumper
        for cls in APPDUMPERS + SYSDUMPERS:
            pnames = globals()[cls].procnames
            if pnames is not None:
                pnames = [p.lower() for p in pnames]
            if (pname is None and pnames is None) or \
               (pname is not None and pnames is not None and pname in pnames):
                if cls in dump._selected_apps or cls in dump._selected_syst:
                    if pname is not None:
                        dump._stats[0].append(pname)  # found
                    self.dumper = globals()[cls](dump, pids)
                    dump.dumpers[cls] = self.dumper
                else:
                    if pname is not None:
                        dump._stats[1].append(pname)  # not selected
                if pname is not None and pnames is not None:
                    return
        if pname is not None:
            dump._stats[2].append(pname)              # not handled


class VolatilityMemDump(object):
    """
    Volatility memory dump class that handles profile search and processes list
     retrieval. It allows either to execute a command from the Python API or to
     call Volatility in a subprocess.
    At processes list creation, it creates a list of Volatility application
     dumpers for the common applications handled by this tool by instantiating
     VolatilityAppDumper. It also provides a 'dump()' method to trigger the
     dumping of resources with the application dumpers.
    """
    class OutputParser(dict):
        """
        Dictionary that parses the output of a Volatility command at creation with:
         - every colon-separated parameter as a (key, value) pair
         - other lines under the 'others' key
        """
        def __init__(self, output):
            """
            Dictionary constructor that parses the Volatility command output.

            :param output: Volatility command output as a string
            """
            if not isinstance(output, str):
                raise ValueError("Bad output variable type (should be str)")
            self['others'] = []
            for line in output.split('\n'):
                line = line.strip().split(':', 1)
                if len(line) == 1:
                    if line[0].strip() != '':
                        self['others'].append(line[0].strip())
                else:
                    self[line[0].strip()] = line[1].strip()
    parsers = {
        'imageinfo': lambda o: VolatilityMemDump.OutputParser(o) \
                               ["Suggested Profile(s)"].split(", "),
    }

    def __init__(self, dump, apps, syst, out_dir="files", plugins_dir=None,
                 profile=None, from_cache=True):
        """
        Determines the profile, retrieves the list of processes and creates the
         list of application dumpers.

        :param dump: Volatility memory dump filename
        :param apps: list of the application dumper classes to be handled
        :param syst: list of the system dumper classes to be handled
        :param out_dir: output directory for retrieved resources
        :param plugins_dir: Volatility custom plugins directory
        :param profile: forced Volatility profile (preceeds from_cache)
        :param from_cache: boolean indicating if the profile must be retrieved
                           from a cache file in /tmp or found by Volatility
        """
        short = dump
        dump = abspath(dump)
        if not isfile(dump):
            raise ValueError("{} is not a dump file".format(dump))
        if any(x not in APPDUMPERS for x in apps):
            raise ValueError("Unknown application dumper(s)")
        if any(x not in SYSDUMPERS for x in syst):
            raise ValueError("Unknown system dumper(s)")
        if plugins_dir is not None and not isdir(plugins_dir):
            raise ValueError("Bad plugins dir")
        if not isinstance(from_cache, bool):
            raise ValueError("Bad from-cache variable type (should be bool)")
        self._artifacts = []
        self._cache = {}
        self._selected_apps = apps
        self._selected_syst = syst
        if len(self._selected_apps) == 0 and len(self._selected_syst) == 0:
            logger.warning("No dumper selected")
            sys.exit(0)
        logger.debug("Setting output directory to '{}'...".format(out_dir))
        self.out_dir = abspath(out_dir)
        if not exists(self.out_dir):
            os.makedirs(self.out_dir)
        self._cachefile = join(self.out_dir, ".cache")
        # initialize dump opening
        registry.PluginImporter()
        self.__is_profile_tested = False
        self.config = conf.ConfObject()
        if plugins_dir is not None:
            plugins_dir = expanduser(plugins_dir)
            logger.debug("Setting plugins directory to '{}'..."
                         .format(plugins_dir))
            self.config.plugins = abspath(plugins_dir)
        for cls in [commands.Command, addrspace.BaseAddressSpace]:
            registry.register_global_options(self.config, cls)
        self.__commands = {k.lower(): v for k, v in \
                          registry.get_plugin_classes(commands.Command).items()}
        self.config.LOCATION = "file://{}".format(dump)
        # get the right dump profile and test it while getting processes
        logger.info("Opening dump file '{}'...".format(short))
        self.__is_profile_tested = self.__get_profile(profile, from_cache)

    def __get_profile(self, profile=None, from_cache=True):
        """
        Get the dump image profile by loading it from a cache file or by running
         'imageinfo' Volatility command.

        :param profile: force profile value (has the precedence on from_cache)
        :param from_cache: load the profile from the cache file if it exists
        :return: boolean indicating if the profile is tested as correct
        """
        if not isinstance(from_cache, bool):
            raise ValueError("From-cache variable should be a boolean")
        cf = self._cachefile
        logger.info("Getting profile...")
        # get available profiles and commands
        available_profiles = self._get_available_profiles()
        if profile is not None and profile not in available_profiles.keys():
            raise ValueError("Bad Volatility profile '{}'".format(profile))
        compatible_profiles = []
        # load profile from 'profile' variable if not None or from cache, or use
        #  the 'imageinfo' command to find it
        self.config.PROFILE = None
        if profile is not None or from_cache:
            if profile is not None:
                self.config.PROFILE = profile
            elif from_cache and isfile(cf):
                with open(cf) as f:
                    self.config.PROFILE = f.readlines()[0].strip()
            if self.config.PROFILE is not None:
                if not self.__get_pslist():
                    self.config.PROFILE = None
                else:
                    compatible_profiles = [self.config.PROFILE]
        if self.config.PROFILE is None:
            self.config.PROFILE = "WinXPSP2x86"  # reset to default
            compatible_profiles = [p for p in self.call('imageinfo',
                                   parser=self.parsers['imageinfo'])]
        self.__profiles = {p: c for p, c in available_profiles.items() \
                           if p in compatible_profiles}
        # try 'pslist' command on the found profile ; if an error occurs, try
        #  the next profile in the list
        cursor, is_profile_tested = 0, False
        while not is_profile_tested and cursor < len(self.__profiles):
            self.config.PROFILE = self.__profiles.keys()[cursor]
            logger.debug("Candidate profile: {}".format(self.config.PROFILE))
            is_profile_tested = self.__get_pslist()
            cursor += 1
        if not is_profile_tested:
            logger.error("No suitable profile could be found ; please check "
                         "that your memory dump is supported by Volatility")
            sys.exit(2)
        self._update_cache(self.config.PROFILE)
        logger.info("> Selected profile: {}".format(self.config.PROFILE))
        return is_profile_tested

    def __get_pslist(self):
        """
        Run 'pslist' Volatility command to check if the profile is correctly
         set, compute the list of processes and attach dumper objects for known
         applications.

        :return: boolean telling if the profile is correct
        """
        if hasattr(self, "processes"):
            return True
        logger.info("Getting processes...")
        try:
            self.processes = self.execute('pslist')
            self.processes.extend(self.execute("psscan"))
        except:
            logger.warning("Wrong profile, re-getting profile...")
            return False
        # collect PIDs relationships
        procs = {'0': "Init"}
        for p in self.processes:
            procs[str(int(p.UniqueProcessId))] = p.ImageFileName
        self.ppids = {}
        for p in self.processes:
            pid = str(int(p.UniqueProcessId))
            ppid = str(int(p.InheritedFromUniqueProcessId))
            try:
                k = (ppid, procs[ppid])
            except KeyError:
                k = (ppid, None)
            self.ppids.setdefault(k, [])
            self.ppids[k].append((pid, procs[pid]))
        # parse the list of processes and create objects for each set of
        #  application instances that are handled by the present tool
        self.dumpers = {}
        self._stats = [[], [], []]
        procnames = set([str(p.ImageFileName) for p in self.processes])
        # first, search for system dumpers
        VolatilityAppDumper(self)
        # second, search for application dumpers per process name
        for n in sorted(procnames, key=lambda n: n.lower()):
            VolatilityAppDumper(self, n.lower())
        for i, t in enumerate(["Found", "Not selected", "Not handled"]):
            s = self._stats[i]
            if len(s) > 0:
                logger.debug("{}: {}".format(t.ljust(12), ", ".join(s)))
        if len(self.dumpers) == 0:
            logger.warning("No application to be handled")
        return True
    
    def _get_available_profiles(self):
        """
        Get the list of available profiles.
        """
        return registry.get_plugin_classes(obj.Profile)
    
    def _update_cache(self, profile=None, dumper=None):
        """
        Update cache file for the current memory dump.
        
        :param profile: profile to be written to the cache
        :param dumper: new dumper to be added to the cache
        """
        if profile is None and dumper is None:
            return
        _ = self._cachefile
        if not exists(_):
            with open(_, 'w') as f:
                f.write(self.config.PROFILE)
        with open(_) as f:
            c = f.read().splitlines()
        p, d = c[0], c[1:]
        if profile is not None:
            c[0] = profile
        if dumper is not None:
            d = sorted(list(set(d + [dumper])))
            c[1:] = d
        with open(_, 'w') as f:
            f.write('\n'.join(c))

    def call(self, command, options=None, parser=None, failmode="silent"):
        """
        Run Volatility with given command and options using subprocess.

        :param command: Volatility command name
        :param options: valid command-related options
        :param parser: None or function for parsing the output
        :param failmode: string indicating the fail mode (error|warn|silent)
        :return: parsed output
        """
        if not isinstance(command, str):
            raise ValueError("Bad command variable type (should be str)")
        if options is not None and not isinstance(options, str):
            raise ValueError("Bad options variable type (should be str)")
        if parser is not None and not callable(parser):
            raise ValueError("Bad parser variable type (should be callable)")
        if failmode not in ["error", "warn", "silent"]:
            raise ValueError("Bad failmode value (should be error|warn|silent)")
        # compose the list of options with already known and input information
        options = [options] if options is not None else []
        if self.__is_profile_tested:
            options.insert(0, "--profile={}".format(self.config.PROFILE))
        filepath = self.config.LOCATION.split("://", 1)[1]
        options.insert(0, "--file=\"{}\"".format(filepath))
        if self.config.plugins is not None and len(self.config.plugins) > 0:
            options.insert(0, "--plugins={}".format(self.config.plugins))
        cmd = CMD.format(cmd=command, opt=" ".join(options))
        # try to get the result from cache first
        if cmd in self._cache:
            logger.debug("> Got result of command '{}' from cache..."
                         .format(command))
            logger.debug(">> {}".format(cmd))
            return self._cache[cmd]
        # run the resulting command with a subprocess
        logger.debug("> Calling command '{}'...".format(command))
        logger.debug(">> {}".format(cmd))
        p = Popen(shlex.split(cmd), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if "ERROR" in err:
            if failmode == "silent":
                return
            if "You must specify something to do (try -h)" in err:
                msg = "Plugin '{}' not found".format(command)
            else:
                msg = "({}) {}".format(*map(lambda x: x.strip(),
                                            err.split(":", 2)[1:3]))
            if failmode == "warn":
                logger.warning(msg)
                return
            elif failmode == "error":
                logger.error(msg)
                raise CalledProcessError(1, cmd)
        out = out.replace('\r\n', '\n')
        # then parse the output with the given parser and return the result
        if parser is not None:
            out = parser(out)
        # cache the result
        self._cache[cmd] = out
        return out
    
    def clean(self):
        """
        Clean up artifacts registered in self._artifacts.
        """
        for a in self._artifacts:
            try:
                os.remove(a)
                logger.debug("Removed '{}'".format(a))
            except OSError:
                logger.debug("Could not remove '{}'".format(a))

    def dump(self, update=False):
        """
        Dump resources for every known application in the memory dump.
        
        :param update: update output directory (meaning that collected pieces of
                        information should not be recollected using Volatility
                        commands)
        """
        if not update and exists(self.out_dir):
            shutil.rmtree(self.out_dir) if isdir(self.out_dir) \
                else os.remove(self.out_dir)
        elif update and isfile(self.out_dir):
            logger.error("Output directory is not valid")
            sys.exit(2)
        if not exists(self.out_dir):
            os.makedirs(self.out_dir)
        # run each dumper and collect information messages for guidance
        d = self.dumpers
        logger.info("Processing {} dumper{}{}..."
                    .format(len(d), ["", "s"][len(d) > 1],
                           ["", ", this may take a while"][len(d) > 3]))
        msgs = {}
        for n, a in d.items():
            logger.debug("Processing dumper '{}'...".format(n))
            for msg in a._run(update):
                msgs.setdefault(msg, [])
                msgs[msg].append(n)
        # finally, warn the collected messages
        for m, n in msgs.items():
            logger.warning("\nThe following applies to collected objects of:\n-"
                           " {}\n\n{}\n".format("\n- ".join(n), m))
    
    def execute(self, command, nopid=False, text=False, parser=None):
        """
        Run Volatility command through the dedicated Python API.

        :param command: Volatility command name
        :param nopid: ensure no PID in the config object (for some commands that
                      search for application artifacts without requiring a PID)
        :param text: convert the result into text
        :param parser: None or function for parsing the output
        :return: parsed output
        """
        if command not in self.__commands.keys():
            raise ValueError("Command does not exist")
        if not isinstance(nopid, bool):
            raise ValueError("Bad nopid variable type (should be bool)")
        if not isinstance(text, bool):
            raise ValueError("Bad text variable type (should be bool)")
        if parser is not None and not callable(parser):
            raise ValueError("Bad parser variable type (should be callable)")
        # try to get the result from cache first
        if command in self._cache:
            logger.debug("> Got result of command '{}' from cache..."
                         .format(command))
            return self._cache[command]
        # run the command with the API
        logger.debug("> Executing command '{}'...".format(command))
        if nopid:
            pid = self.config.PID
            self.config.PID = None
        command = self.__commands[command](deepcopy(self.config))
        result = command.calculate()
        # convert the result to text if required
        if text:
            io = StringIO.StringIO()
            command.render_text(io, result)
            out = io.getvalue().replace('\r\n', '\n')
        else:
            out = list(result)
        if nopid:
            self.config.PID = pid
        # then parse the output with the given parser and return the result
        if parser:
            out = parser(out)
        # cache the result
        self._cache[command] = out
        return out
