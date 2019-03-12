#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging
from os import listdir
from os.path import abspath, basename, isdir, isfile, join, splitext
from pyunpack import Archive, PatoolError
from subprocess import check_output


__all__ = ["decompress"]
logger = logging.getLogger("main")

ARCHIVE_EXCL = lambda f: basename(f) in ["README", "README.md"] or \
                         f.endswith(".txt")


def decompress(filename, temp_dir):
    """
    Attempts to decompress the input file to a temporary folder. If Patool fails
     to unpack it, it is assumed that the file is not an archive.

    :param filename: path to the input file
    :param temp_dir: temporary directory for decompressed files
    :return:         list of files (these extracted if decompression was
                      performed or the input filename otherwise)
    """
    # set the temporary folder name
    base, ext = splitext(basename(filename))
    base, ext2 = splitext(base)
    if ext2 != '':
        ext = ext2
    tmp_dir = join(abspath(temp_dir), base)
    # try to list files from the archive (do not re-decompress if files are
    #  already present)
    if isdir(tmp_dir) and len(listdir(tmp_dir)) > 0:
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
            logger.exception(e)
    # retrieve the list of extracted files
    return True, [join(tmp_dir, fn) for fn in listdir(tmp_dir) \
                  if not ARCHIVE_EXCL(fn)]
