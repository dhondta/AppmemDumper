#!/usr/bin/python2
# -*- coding: UTF-8 -*-
# --------------------------- DOCUMENTATION SECTION ---------------------------
__author__ = "Alexandre D'Hondt"
__version__ = "1.0"
__copyright__ = "AGPLv3 (http://www.gnu.org/licenses/agpl.html)"
__reference__ = "Ms Cybersecurity / INFO-Y64 - Intro to Digital Forensics"
__doc__ = """
This self-contained tool automates the research of some artifacts for forensics
 purpose in memory dumps based upon Volatility for a series of common Windows
 applications.

It can also open multiple archive formats. In case of an archive, the tool will
 extract all its files to a temporary directory and then try to open each file
 as a memory dump (except files named README or README.md).

Design principles:
- maximum use of Python-builtin modules
- for non-standard imports, trigger exit if not installed and display the
  command for installing these
- no modularity (principle of self-contained tool) so that it can simply be
  copied in /usr/bin with dependencies other thant the non-standard imports
"""
__examples__ = ["memory.dmp", "my-dumps.tar.gz", "dump.raw -a 0,1 -f"]
__print__ = "Print documentation:\n- stdout: pydoc {0}\n- html  : pydoc -w {0}"

# ------------------------------ IMPORTS SECTION ------------------------------
import argparse
import logging
import os
import re
import shutil
import signal
import string
import StringIO
import sys
from collections import deque
from copy import deepcopy
from subprocess import check_output, CalledProcessError, PIPE, Popen
# non-standard imports with warning if dependencies are missing
try:
    from pyunpack import Archive, PatoolError
except OSError:
    print("Missing dependencies, please run 'sudo pip install pyunpack'")
    sys.exit(1)
try:
    import volatility.addrspace as addrspace
    import volatility.conf as conf
    import volatility.commands as commands
    import volatility.constants as constants
    import volatility.debug as debug
    import volatility.obj as obj
    import volatility.registry as registry
    import volatility.utils as utils
except ImportError:
    print("Missing dependencies, please run 'sudo apt-get install volatility'")
    sys.exit(1)
try:
    Popen(["foremost", "-h"], stdout=PIPE, stderr=PIPE)
except OSError:
    print("Missing dependencies, please run 'sudo apt-get install foremost'")
    sys.exit(1)
# colorize logging
try:
    import coloredlogs
    colored_logs_present = True
except:
    print("(Install 'coloredlogs' for colored logging)")
    colored_logs_present = False


# ----------------------------- CONSTANTS SECTION -----------------------------
SCRIPT, _ = os.path.splitext(os.path.basename(__file__))
LOG_FORMAT = '[%(name)s] %(asctime)s [%(levelname)s] %(message)s'
DATE_FORMAT = '%H:%M:%S'
CMD = 'volatility {opt} {cmd}'
ARCHIVE_EXCL = lambda f: os.path.basename(f) in ["README", "README.md"] \
                         or f.endswith(".txt")


# ------------------------------ HELPERS SECTION ------------------------------
def exit_handler(signal=None, frame=None, code=0):
    """
    Exit handler.

    :param signal: signal number
    :param stack: stack frame
    :param code: exit code
    """
    logging.shutdown()
    sys.exit(code)
# bind termination signal (Ctrl+C) to exit handler
signal.signal(signal.SIGINT, exit_handler)


def help_description(d):
    """
    Help description formatting function to add global documentation variables.

    :param d: help description
    :return: the formatted help description
    """
    s = ''.join([x.capitalize() for x in __file__
                 .replace('./', '').replace('.py', '').split('-')])
    if '__version__' in globals():
        s += " v" + __version__
    for v in ['__author__', '__copyright__', '__reference__', '__source__',
              '__training__']:
        if v in globals():
            s += "\n%s: %s" % (v.strip('_').capitalize(), eval(v))
    return s + "\n\n" + d


def help_epilog():
    """
    Help epilog formatting function to add global documentation variables.

    :return: the formatted help epilog
    """
    e = ""
    if '__examples__' in globals() and len(__examples__ or []) > 0:
        ex = ["  python {0} {1}".format(SCRIPT, x) for x in __examples__]
        e += "Usage examples:\n" + '\n'.join(ex)
    if '__print__' in globals():
        e += "\n\n{}".format(__print__.format(SCRIPT))
    return e


# ----------------------------- FUNCTIONS SECTION -----------------------------
def __decompress(filename, temp_dir):
    """
    Attempts to decompress the input file to a temporary folder. If Patool fails
     to unpack it, it is assumed that the file is not an archive.

    :param filename: path to the input file
    :param temp_dir: temporary directory for decompressed files
    :return: list of files (these extracted if decompression was performed or
             the input filename otherwise)
    """
    # set the temporary folder name
    basename = os.path.basename(filename)
    base, ext = os.path.splitext(basename)
    base, ext2 = os.path.splitext(base)
    if ext2 != '':
        ext = ext2
    tmp_dir = os.path.join(os.path.abspath(temp_dir), base)
    # try to list files from the archive (do not re-decompress if files are
    #  already present)
    if os.path.isdir(tmp_dir) and len(os.listdir(tmp_dir)) > 0:
        logger.info("Listing files from '{}'...".format(filename))
        try:
            out = check_output(["patool", "list", filename])
            files, bad = [], False
            for line in out.split('\n'):
                if line.startswith("patool: "):
                    break
                fn = os.path.join(tmp_dir, line)
                if not os.path.isfile(fn) and not ARCHIVE_EXCL(fn):
                    bad = True
                    break
                if not ARCHIVE_EXCL(fn):
                    files.append(fn)
            if not bad:
                # if all required files are already decompressed, just return
                #  the list of file paths
                return True, files
        except CalledProcessError:
            logger.debug("Not an archive, continuing...")
            return False, [filename]
    # now extract files
    logger.info("Decompressing '{}' (if archive)...".format(filename))
    archive = Archive(filename)
    try:
        archive.extractall(tmp_dir, auto_create_dir=True)
    except (PatoolError, ValueError) as e:
        if str(e).startswith("patool can not unpack"):
            logger.debug("Not an archive, continuing...")
            return False, [filename]
        else:
            logger.error(e)
            exit_handler(code=2)
    # retrieve the list of extracted files
    return True, [os.path.join(tmp_dir, fn) for fn in os.listdir(tmp_dir) \
                  if not ARCHIVE_EXCL(fn)]


# ------------------------------ CLASSES SECTION ------------------------------
class VolatilityOutputParser(dict):
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
        assert isinstance(output, str)
        self['others'] = []
        for line in output.split('\n'):
            line = line.strip().split(':', 1)
            if len(line) == 1:
                if line[0].strip() != '':
                    self['others'].append(line[0].strip())
            else:
                self[line[0].strip()] = line[1].strip()


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
    parsers = {
        'imageinfo': lambda o: VolatilityOutputParser(o) \
                               ["Suggested Profile(s)"].split(", "),
    }

    def __init__(self, dump, selected_apps, out_dir="files", plugins_dir=None,
                 from_cache=True):
        """
        Determines the profile, retrieves the list of processes and creates the
         list of application dumpers.

        :param dump: Volatility memory dump filename
        :param selected_apps: list of the application names to be handled
        :param out_dir: output directory for retrieved resources
        :param plugins_dir: Volatility custom plugins directory
        :param from_cache: boolean indicating if the profile must be retrieved
                           from a cache file in /tmp or found by Volatility
        """
        short = dump
        dump = os.path.abspath(dump)
        assert os.path.isfile(dump)
        assert all(x in [n for n, _ in apps] for x in selected_apps)
        assert plugins_dir is None or os.path.isdir(plugins_dir)
        assert isinstance(from_cache, bool)
        self._selected_apps = selected_apps
        logger.debug("Setting output directory to '{}'...".format(out_dir))
        self.out_dir = os.path.abspath(out_dir)
        # initialize dump opening
        registry.PluginImporter()
        self.__is_profile_tested = False
        self.config = conf.ConfObject()
        if plugins_dir is not None:
            logger.debug("Setting plugins directory to '{}'..."
                         .format(plugins_dir))
            self.config.plugins = os.path.abspath(plugins_dir)
        for cls in [commands.Command, addrspace.BaseAddressSpace]:
            registry.register_global_options(self.config, cls)
        self.__commands = {k.lower(): v for k, v in \
                          registry.get_plugin_classes(commands.Command).items()}
        self.config.LOCATION = "file://{}".format(dump)
        # get the right dump profile and test it while getting processes
        logger.info("Opening dump file '{}'...".format(short))
        self.__is_profile_tested = self.__get_profile(from_cache)

    def __get_profile(self, from_cache=True):
        """
        Get the dump image profile by loading it from a cache file or by running
         'imageinfo' Volatility command.

        :param from_cache: load the profile from the cache file if it exists
        :return: boolean indicating if the profile is tested as correct
        """
        assert isinstance(from_cache, bool)
        logger.info("Getting profile...")
        # get available profiles and commands
        available_profiles = registry.get_plugin_classes(obj.Profile)
        compatible_profiles = []
        # load profile from cache or use the 'imageinfo' command to find it
        tmp = "/tmp/{}/profile".format(SCRIPT)
        if from_cache:
            if os.path.isfile(tmp):
                with open(tmp) as f:
                    self.config.PROFILE = f.read().strip()
                if not self.__get_pslist():
                    self.config.PROFILE = None
                else:
                    compatible_profiles = [self.config.PROFILE]
            else:
                from_cache = False
        if not from_cache or self.config.PROFILE is None:
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
            logger.debug("Profile: {}".format(self.config.PROFILE))
            is_profile_tested = self.__get_pslist()
            cursor += 1
        if not is_profile_tested:
            logger.error("No suitable profile could be found ; please check "
                         "that your memory dump is supported by Volatility")
            exit_handler(code=2)
        # create a cache file with the profile name
        if not os.path.isdir(os.path.dirname(tmp)):
            os.makedirs(os.path.dirname(tmp))
        with open(tmp, 'w') as f:
            f.write(self.config.PROFILE)
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
        except:
            logger.debug("Wrong profile, re-getting profile...")
            return False
        # parse the list of processes and create objects for each set of
        #  application instances that are handled by the present tool
        self.apps = {}
        self._stats = [[], [], []]
        procnames = set([str(p.ImageFileName) for p in self.processes])
        # first, search for general-purpose dumpers
        VolatilityAppDumper(self)
        # second, search for specific-purpose dumpers per process name
        for n in sorted(procnames, key=lambda n: n.lower()):
            VolatilityAppDumper(self, n.lower())
        for i, t in enumerate(["Found", "Not selected", "Not handled"]):
            s = self._stats[i]
            if len(s) > 0:
                logger.debug("{}: {}".format(t.ljust(12), ", ".join(s)))
        if len(self.apps) == 0:
            logger.warn("No application to be handled")
        return True

    def call(self, command, options=None, parser=None, silentfail=False):
        """
        Run Volatility with given command and options using subprocess.

        :param command: Volatility command name
        :param options: valid command-related options
        :param parser: None or function for parsing the output
        :param silentfail: boolean to make the call fail silently or not
        :return: parsed output
        """
        assert isinstance(command, str)
        assert options is None or isinstance(options, str)
        assert parser is None or callable(parser)
        assert isinstance(silentfail, bool)
        # compose the list of options with already known and input information
        options = [options] if options is not None else []
        if self.__is_profile_tested:
            options.insert(0, "--profile={}".format(self.config.PROFILE))
        filepath = self.config.LOCATION.split("://", 1)[1]
        options.insert(0, "--file={}".format(filepath))
        if self.config.plugins is not None and len(self.config.plugins) > 0:
            options.insert(0, "--plugins={}".format(self.config.plugins))
        cmd = CMD.format(cmd=command, opt=" ".join(options))
        # run the resulting command with a subprocess
        logger.debug("> Calling command '{}'...".format(command))
        logger.debug(">> {}".format(cmd))
        p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if "ERROR" in err:
            if silentfail:
                return
            else:
                logger.error(err.split(":", 1)[1].strip())
                raise CalledProcessError(1, cmd)
        out = out.replace('\r\n', '\n')
        # then parse the output with the given parser and return the result
        if parser is not None:
            out = parser(out)
        return out

    def dump(self):
        """
        Dump resources for every known application in the memory dump.
        """
        if os.path.exists(self.out_dir):
            shutil.rmtree(self.out_dir) if os.path.isdir(self.out_dir) \
                else os.remove(self.out_dir)
        os.makedirs(self.out_dir)
        # run each dumper and collect information messages for guidance
        msgs = {}
        for n, a in self.apps.items():
            logger.info("Processing dumper '{}'...".format(n))
            for msg in a._run():
                msgs.setdefault(msg, [])
                msgs[msg].append(n)
        # finally, warn the collected messages
        for m, n in msgs.items():
            logger.warn("\nThe following applies to collected objects of:\n- {}"
                        "\n\n{}\n".format("\n- ".join(n), m))
            
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
        assert command in self.__commands.keys()
        assert isinstance(nopid, bool)
        assert isinstance(text, bool)
        assert parser is None or callable(parser)
        logger.debug("> Executing command '{}'...".format(command))
        if nopid:
            pid = self.config.PID
            self.config.PID = None
        # run the command with the API
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
        return out


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
        assert isinstance(dump, VolatilityMemDump)
        assert pname is None or isinstance(pname, str)
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
        # if no process name was given and there exists a general-purpose dumper
        #  (that has no list of process names), create a dumper
        for app, cls in apps:
            pnames = globals()[cls].procnames
            if pnames is not None:
                pnames = [p.lower() for p in pnames]
            if (pname is None and pnames is None) or \
               (pname is not None and pnames is not None and pname in pnames):
                if app in dump._selected_apps:
                    if pname is not None:
                        dump._stats[0].append(pname)  # found
                    name = pname.split('.', 1)[0] if pname is not None else app
                    self.dumper = globals()[cls](dump, name, pids)
                    dump.apps[app] = self.dumper
                else:
                    if pname is not None:
                        dump._stats[1].append(pname)  # not selected
                if pname is not None and pnames is not None:
                    return
        if pname is not None:
            dump._stats[2].append(pname)              # not handled


class GenericDumper(object):
    """
    Generic dumper class for handling base operations on the memory dump for
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
        assert isinstance(dump, VolatilityMemDump)
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
        d = os.path.join(self.dump.out_dir, *subdirs)
        if not os.path.isdir(d):
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
        dest = os.path.join(self.dump.out_dir,
                            self._resname(self.dump.config.PID, cmd, fmt))
        with open(dest, 'wb') as f:
            f.write(content)
        if verbose:
            logger.info("> {}".format(os.path.relpath(dest)))

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
        src = os.path.join(self.dump.out_dir, "{}.dmp".format(pid))
        dst = os.path.join(self.dump.out_dir, self._resname(pid, cmd, "data"))
        shutil.move(src, dst)
        if verbose:
            logger.info("> {}".format(dst))
        return dst

    def _memsearch(self):
        """
        Executes the 'memdump' Volatility command then parse the collected dump
         against used-defined regular expressions.
        Valid patterns structure:
          self.re_patterns := list(tuples(re_pattern, format, short_descr))
        """
        if not hasattr(self, "re_patterns"):
            logger.warn("No memory search performed (no pattern found)")
            return
        dump = self._memdump(verbose=False)
        with open(dump) as f:
            content = f.read()
        for pattern, fmt, descr in self.re_patterns:
            r = re.compile(pattern, re.M + re.S)
            out = r.search(content)
            if out is not None:
                self._dump_file(out.group(), 'memdump-{}'.format(descr), fmt)
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
            logger.warn("No VAD search performed (no pattern found)")
            return
        dump_dir = self._vaddump(verbose=False)
        for fn in os.listdir(dump_dir):
            with open(os.path.join(dump_dir, fn), 'rb') as f:
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

    def carve(self, filepath, types=(), clean=False):
        """
        Carve files of given types from the input resource with Foremost.

        :param filepath: file path of the resource to be carved
        :param types: list of extensions to be carved from the resource
        """
        assert os.path.isfile(filepath)
        assert (isinstance(types, tuple) or isinstance(types, list)) and \
               all(isinstance(x, str) for x in types)
        assert isinstance(clean, bool)
        logger.debug("> Carving with Foremost...")
        folder, _ = os.path.splitext(filepath)
        opt = ["", "-t {}".format(",".join(types))][len(types) > 0]
        cmd = "foremost {} -o {} {}".format(filepath, folder, opt)
        logger.debug(">> {}".format(cmd))
        p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        with open(os.path.join(folder, "audit.txt")) as f:
            disp = False
            for line in f.readlines():
                line = line.strip()
                if "Finish:" in line:
                    break
                if all([x in line for x in ("Num", "Name", "Size", "Comment")]):
                    disp = True
                if disp and len(line) > 0 and ":" in line:
                    fn = line.split(":", 1)[1].strip().split()[0]
                    _, ext = os.path.splitext(fn)
                    fp = os.path.join(folder, ext[1:], fn)
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


# -------------------- GENERAL-PURPOSE DUMPERS SECTION -------------------------
class DumpInfoDumper(GenericDumper):
    """
    Dumper of general information about the memory image.
    """
    def run(self):
        """
        Executes a series of informational Volatility commands.
        """
        for cmd in ['crashinfo', 'hibinfo', 'vboxinfo', 'vmwareinfo']:
            self._dump_file(self.dump.call(cmd, silentfail=True), cmd)


class UserHashesDumper(GenericDumper):
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


# ------------------ APPLICATION-RELATED DUMPERS SECTION -----------------------
class NotepadDumper(GenericDumper):
    """
    Dumper for the well-known application Notepad built in Microsoft Windows. It
     tries the 'notepad' plugin, then tries the 'editbox' plugin or finally gets
     the text contained in the edition control box of the main window of Notepad
     from a VAD node based on a pattern.
    """
    procnames = ["notepad.exe"]
    fmt_patterns = [("\xf2\xf3\xf3\xff\xf1\xf2\xf2\xff\xf0\xf1\xf0\xff\xf0"
                     "\xf1\xf1\xff", "\x00" * 16, "txt")]

    def run(self):
        """
        Executes the 'editbox' Volatility command.
        """
        # Try 1: use 'notepad' command (only for profiles <= WinXP...
        if not hasattr(self, "_no_notepad"):
            cmd = 'notepad'
            try:
                out = self.dump.execute(cmd, text=True)
                text = out.split("Text:\n", 1)[1]
                self._dump_file(text, cmd)
                return
            except IndexError:
                logger.debug("Nothing found with 'notepad'")
            except:
                logger.debug("'notepad' does not support the current profile")
                self._no_notepad = True
        # Try 2: use 'editbox'
        cmd = 'editbox'
        out = self.dump.execute(cmd, text=True)
        out = out.split("******************************\n")
        for result in out[1:]:
            meta, text = result.split("-------------------------\n")
            pid = VolatilityOutputParser(meta)['Process ID']
            if self.dump.config.PID == pid:
                self._dump_file(text, cmd)
                return
        logger.debug("Nothing found with 'editbox'")
        # Try 3: use 'vaddump' and search for patterns in VAD nodes
        self._vadsearch(reduce_text=True)


class MSPaintDumper(GenericDumper):
    """
    Dumper for the well-known application Paint built in Microsoft Windows. It
     uses the 'run()' method of GenericDumper to extract the memory of the
     process for further analysis using the 'memdump' Volatility command.
    """
    procnames = ["mspaint.exe"]
    messages = GenericDumper._predef_messages[0:1]

    def run(self):
        self._memdump()


class MediaPlayerClassicDumper(GenericDumper):
    """
    Dumper for the common application Media Player Classic. It performs the same
     operations as MSPaintDumper.
    """
    procnames = ["mpc-hc.exe"]
    messages = GenericDumper._predef_messages[0:1]

    def run(self):
        self._memdump()


class WordpadDumper(GenericDumper):
    """
    Dumper for the well-known application Wordpad built in Microsoft Windows. It
     uses the 'run()' method of GenericDumper to extract the memory of the
     process for further analysis using the 'memdump' Volatility command. It
     also uses the 'carve()' method of GenericDumper to extract image resources
     and executes the 'vaddump' Volatility command for retrieving Virtual
     Address Descriptor (VAD) objects for later manual analysis.
    """
    procnames = ["wordpad.exe"]
    messages = GenericDumper._predef_messages[0:2]

    def run(self):
        """
        Executes the 'memdump' Volatility command (GenericDumper), carves files
         with Foremost then executes the 'editbox' Volatility command.
        """
        self.carve(self._memdump(verbose=False), ('jpg', 'png',), clean=True)
        # TODO: find patterns for searching into the VAD nodes
        # self._vaddump()


class AdobeReaderDumper(GenericDumper):
    """
    Dumper for the well-known application Adobe Reader. It uses the 'run()'
     method of GenericDumper to extract the memory of the process and carves PDF
     files on it with Foremost then removes the memory dump.
    """
    procnames = ["reader.exe", "AcroRd32.exe"]

    def run(self):
        """
        Executes the 'memdump' Volatility command (GenericDumper), carves PDF
         files with Foremost then removes the process memory dump.
        """
        self.carve(self._memdump(verbose=False), ('pdf',), clean=True)


class PDFLiteDumper(AdobeReaderDumper):
    """
    Dumper for the common application PDFLite. It performs the same operations
     as AdobeReaderDumper.
    """
    procnames = ["PDFlite.exe"]


class FoxitReaderDumper(AdobeReaderDumper):
    """
    Dumper for the common application Foxit Reader. It performs the same
     operations as AdobeReaderDumper.
    """
    procnames = ["FoxitReader.ex", "FoxitReader.exe"]


class SumatraPDFDumper(AdobeReaderDumper):
    """
    Dumper for the common application Sumatra PDF. It performs the same
     operations as AdobeReaderDumper.
    """
    procnames = ["SumatraPDF.exe"]


class KeePassDumper(GenericDumper):
    """
    Dumper for the common application KeePass.
    """
    procnames = ["KeePass.exe", "KeePassX.exe", "PassKeep.exe"]
    messages = ["If the KeePass database was used with a master password ;\n"
                "1. Its hash can be recovered using 'keepass2john'\n"
                "2. It can then be cracked with 'john'"]
    # https://github.com/Stoom/KeePass/wiki/KDBX-v2-File-Format
    fmt_patterns = [("\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5", "\x00" * 16, "kdb"),
                    ("\x03\xd9\xa2\x9a\x66\xfb\x4b\xb5", "\x00" * 16, "kdbx"),
                    ("\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", "\x00" * 16, "kdbx")]
    re_patterns = [(r'(<\?xml(\s[a-z0-9\=\-\"\'\._]+)+\?>\r?\n<KeePassFile>'
                     '(.*?)<\/KeePassFile>)', "xml", "file"),
                   (r'(<\?xml(\s[a-zA-Z0-9\=\-\"\'\.\:\/_]+)+\?>\r?\n'
                     '<ArrayOfString(\s[a-zA-Z0-9\=\-\"\'\.\:\/_]+)+>'
                     '(.*?)<\/ArrayOfString>)', "xml", "path")]

    def run(self):
        """
        Executes the 'memdump' Volatility command (GenericDumper), retrieves
         some XML content, then executes the 'vaddump' Volatility command and
         finally gets the KeePass DB from the VAD nodes.
        """
        self._memsearch()
        self._vadsearch(include_pattern=True)


class TrueCryptDumper(GenericDumper):
    """
    Dumper for the common application TrueCrypt.
    """
    procnames = ["TrueCrypt.exe"]

    def run(self):
        """
        Executes the 'memdump' Volatility command (GenericDumper) and the
         TrueCrypt-related Volatility commands.
        """
        self._memdump()
        for cmd in ['truecryptmaster', 'truecryptpassphrase',
                    'truecryptsummary']:
            self._dump_file(self.dump.call(cmd), cmd)


class InternetExplorerDumper(GenericDumper):
    """
    Dumper for the common application Microsoft Internet Explorer.
    """
    procnames = ["iexplore.exe"]

    def run(self):
        """
        Executes the 'iehistory' Volatility command.
        """
        cmd = 'iehistory'
        self._dump_file(self.dump.call(cmd), cmd)


class FirefoxDumper(GenericDumper):
    """
    Dumper for the common application Mozilla Firefox.
    """
    procnames = ["firefox.exe"]

    def run(self):
        """
        Executes the Firefox-related Volatility community plugins.
        """
        try:
            for cmd in ['firefoxcookies', 'firefoxdownloads', 'firefoxhistory']:
                self._dump_file(self.dump.call(cmd, "--output=csv"), cmd, 'csv')
        except CalledProcessError:
            logger.warn("Firefox plugins are not built in Volatility ; please"
                        " ensure that you used the -p option to set the path"
                        " to custom plugins.")


class OpenOfficeDumper(GenericDumper):
    """
    Dumper for the common OpenOffice suite.
    """
    procnames = ["soffice.exe", "soffice.bin", "swriter.exe", "scalc.exe",
                 "simpress.exe", "sdraw.exe", "sbase.exe", "smath.exe",
                 "sweb.exe"]
    # https://ubuntuforums.org/showthread.php?t=1378119
    re_patterns = [(r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.textP'
                    r'K(.*?)META-INF/manifest.xmlPK.{20}', "odt", "text"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.sprea'
                    r'dsheetPK(.*?)META-INF/manifest.xmlPK.{20}', "ods",
                    "spreadsheet"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.prese'
                    r'ntationPK(.*?)META-INF/manifest.xmlPK.{20}', "odp",
                    "presentation"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.graph'
                    r'icsPK(.*?)META-INF/manifest.xmlPK.{20}', "odg",
                    "graphics"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.chart'
                    r'PK(.*?)META-INF/manifest.xmlPK.{20}', "odc", "chart"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.formu'
                    r'laPK(.*?)META-INF/manifest.xmlPK.{20}', "odf",
                    "formula"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.image'
                    r'PK(.*?)META-INF/manifest.xmlPK.{20}', "odi", "image"),
                   (r'(PK).{28}mimetypeapplication/vnd.oasis.opendocument.text-'
                    r'masterPK(.*?)META-INF/manifest.xmlPK.{20}', "odm",
                    "textmaster"),
                   (r'(PK).{28}mimetypeapplication/vnd.sun.xml.writerPK(.*?)'
                    r'META-INF/manifest.xmlPK.{20}', "sxw", "writer")]

    def run(self):
        """
        Executes the 'memdump' Volatility command (GenericDumper) and retrieves
         OpenOffice documents.
        """
        self._memsearch()


# ------------------------------- MAIN SECTION --------------------------------
global logger, apps
classes = [c for c in globals().keys() if c.endswith("Dumper") and \
           c not in ["VolatilityAppDumper", "GenericDumper"]]
__all__ = ["VolatilityMemDump", "GenericDumper"] + classes
apps = sorted([(c[:-6].lower(), c) for c in classes], key=lambda x: x[0])
logging.basicConfig(format=LOG_FORMAT, datefmt=DATE_FORMAT, level=logging.DEBUG)
logger = logging.getLogger(SCRIPT)
if __name__ == '__main__':
    appsl = '\n'.join("  [{}] {}{}".format(i, a[0], ["", "*"][globals()[a[1]] \
                      .procnames is None]) for i, a in enumerate(apps))
    parser = argparse.ArgumentParser(
        prog=SCRIPT, description=help_description(__doc__),
        epilog=help_epilog(), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("dump", help="memory dump file path")
    parser.add_argument("-a", dest="apps", default="*", help="comma-separated "
                        "list of integers designating applications to be parsed"
                        " (default: *)\n Currently supported: \n{}\n (*:"
                        " general-purpose dumper)".format(appsl))
    parser.add_argument("-d", dest="dump_dir", default="files",
                        help="dump directory (default: ./files/)")
    parser.add_argument("-f", dest="force", action="store_true",
                        help="force profile search, do not use cached profile"
                             " (default: false)")
    parser.add_argument("-p", dest="plugins", help="path to the custom plugins"
                                                   " directory (default: none)")
    parser.add_argument("-t", dest="temp_dir", default=".temp",
                        help="temporary directory for decompressed images"
                             " (default: ./.temp/)")
    parser.add_argument("-v", dest="verbose", action="store_true",
                        help="verbose mode (default: false)")
    args = parser.parse_args()
    sys.argv = sys.argv[:1]  # remove arguments for avoiding passing them to the
                             #  Volatility API (e.g. -p will cause a clash with
                             #  the PID option of Volatility)
    # configure logging and get the root logger
    args.verbose = [logging.INFO, logging.DEBUG][args.verbose]
    logging.basicConfig(format=LOG_FORMAT, datefmt=DATE_FORMAT,
                        level=args.verbose)
    logger = logging.getLogger(SCRIPT)
    if colored_logs_present:
        coloredlogs.DEFAULT_LOG_FORMAT = LOG_FORMAT
        coloredlogs.DEFAULT_DATE_FORMAT = DATE_FORMAT
        coloredlogs.install(args.verbose)
    for l in ['pyunpack', 'easyprocess', 'volatility.debug']:
        logging.getLogger(l).setLevel(51)
    # arguments validation
    exit_app = False
    n = len(apps)
    if not os.path.isfile(args.dump):
        logger.error("Dump file does not exist !")
        exit_app = True
    if args.apps == "*":
        args.apps = list(range(n))
    else:
        try:
            args.apps = [int(i) for i in args.apps.split(",")]
        except ValueError:
            logger.error("Expected comma-separated list of int")
            exit_app = True
        if any(i not in range(n) for i in args.apps):
            logger.error("Expected int in range({})".format(n))
            exit_app = True
    args.apps = [apps[i][0] for i in args.apps]
    if not os.path.isdir(args.dump_dir):
        try:
            os.makedirs(args.dump_dir)
        except OSError as e:
            logger.error(e)
            exit_app = True
    if not os.path.isdir(args.temp_dir):
        try:
            os.makedirs(args.temp_dir)
        except OSError as e:
            logger.error(e)
            exit_app = True
    if args.plugins is not None and not os.path.isdir(args.plugins):
        logger.warn("Bad input plugins directory ; setting ignored.")
        args.plugins = None
    if exit_app:
        exit_handler(code=2)
    # running the main stuff
    archive, args.dump = __decompress(args.dump, args.temp_dir)
    try:
        from_cache = not args.force
        for dump in args.dump:
            dump_dir = os.path.join(args.dump_dir, os.path.basename(dump))
            VolatilityMemDump(dump, args.apps, dump_dir,
                              args.plugins, from_cache).dump()
            # if archive, assume that every other dump has the same profile as
            #  the first one in order to spare time
            from_cache = True
        # clean the extracted files' folder
        shutil.rmtree(args.temp_dir)
    except Exception as e:
        logger.exception("Unexpected error: {}".format(str(e)))
        exit_handler(code=1)
    # gracefully close after running the main stuff
    exit_handler()
