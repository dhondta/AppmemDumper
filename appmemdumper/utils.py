#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from argparse import Action
from os import listdir
from os.path import abspath, basename, isdir, isfile, join, splitext
from pyunpack import Archive, PatoolError


__all__ = ["decompress", "CommaListOfInts"]

ARCHIVE_EXCL = lambda f: basename(f) in ["README", "README.md"] or \
                         f.endswith(".txt")


def decompress(filename, temp_dir, logger=None):
    """
    Attempts to decompress the input file to a temporary folder. If Patool fails
     to unpack it, it is assumed that the file is not an archive.

    :param filename: path to the input file
    :param temp_dir: temporary directory for decompressed files
    :param logger:   self-explanatory
    :return:         list of files (these extracted if decompression was
                      performed or the input filename otherwise)
    """
    # set the temporary folder name
    basename = basename(filename)
    base, ext = splitext(basename)
    base, ext2 = splitext(base)
    if ext2 != '':
        ext = ext2
    tmp_dir = join(abspath(temp_dir), base)
    # try to list files from the archive (do not re-decompress if files are
    #  already present)
    if isdir(tmp_dir) and len(listdir(tmp_dir)) > 0:
        if logger:
            logger.info("Listing files from '{}'...".format(filename))
        try:
            out = check_output(["patool", "list", filename])
            files, bad = [], False
            for line in out.split('\n'):
                if line.startswith("patool: "):
                    break
                fn = join(tmp_dir, line)
                if not isfile(fn) and not ARCHIVE_EXCL(fn):
                    bad = True
                    break
                if not ARCHIVE_EXCL(fn):
                    files.append(fn)
            if not bad:
                # if all required files are already decompressed, just return
                #  the list of file paths
                return True, files
        except CalledProcessError:
            if logger:
                logger.debug("Not an archive, continuing...")
            return False, [filename]
    # now extract files
    if logger:
        logger.info("Decompressing '{}' (if archive)...".format(filename))
    archive = Archive(filename)
    try:
        archive.extractall(tmp_dir, auto_create_dir=True)
    except (PatoolError, ValueError) as e:
        if str(e).startswith("patool can not unpack"):
            if logger:
                logger.debug("Not an archive, continuing...")
            return False, [filename]
        else:
            if logger:
                logger.exception(e)
    # retrieve the list of extracted files
    return True, [join(tmp_dir, fn) for fn in listdir(tmp_dir) \
                  if not ARCHIVE_EXCL(fn)]


class CommaListOfInts(Action):
    """ Parses a comma-separated list of ints. """
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed for CommaListOfInts")
        super(CommaListOfInts, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        if value == "*":
            l = list(range(len(DUMPERS)))
        else:
            try:
                l = list(map(int, value.split(',')))
            except:
                raise ValueError("{} could not be parsed".format(value))
        setattr(namespace, self.dest, [DUMPERS[i] for i in l])
