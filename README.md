[![PyPi](https://img.shields.io/pypi/v/appmemdumper.svg)](https://pypi.python.org/pypi/appmemdumper/)
[![Build Status](https://travis-ci.org/dhondta/AppmemDumper.svg?branch=master)](https://travis-ci.org/dhondta/AppmemDumper)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.804958.svg)](https://doi.org/10.5281/zenodo.804958)
[![Python Versions](https://img.shields.io/pypi/pyversions/appmemdumper.svg)](https://pypi.python.org/pypi/appmemdumper/)
[![Requirements Status](https://requires.io/github/dhondta/AppmemDumper/requirements.svg?branch=master)](https://requires.io/github/dhondta/AppmemDumper/requirements/?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/AppmemDumper/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/AppmemDumper?targetFile=requirements.txt)
[![License](https://img.shields.io/pypi/l/appmemdumper.svg)](https://pypi.python.org/pypi/appmemdumper/)


## Table of Contents

   * [Introduction](#introduction)
   * [System Requirements](#system-requirements)
   * [Installation](#installation)
   * [Quick Start](#quick-start)
   * [Issues management](#issues-management)


## Introduction

This tool automates the research of some artifacts for forensics purpose in memory dumps based upon Volatility for a series of common Windows applications.

It can also open multiple archive formats. In case of an archive, the tool will extract all its files to a temporary directory and then try to open each file as a memory dump (except files named README or README.md).


## System Requirements

This framework was tested on an Ubuntu 18.04 with Python 2.7.


## Installation

1. Install system requirements

 ```session
 $ sudo apt-get install foremost
 $ git clone https://github.com/volatilityfoundation/volatility /tmp/vol-setup
 $ cd /tmp/vol-setup && sudo python setup.py install
 ```

 > **Behind a proxy ?**
 > 
 > Do not forget to configure your Network system settings (or manually edit `/etc/apt/apt.conf`).
 
2. Install AppMemDumper from Pip

 ```session
 $ pip install appmemdumper
 ```

 > **Behind a proxy ?**
 > 
 > Do not forget to add option `--proxy=http://[user]:[pwd]@[host]:[port]` to your pip command.


## Quick Start

1. Help

 ```session
$ app-mem-dumper -h
usage: app-mem-dumper [-a APPS] [-d DUMP_DIR] [-f] [-p PLUGINS_DIR]
                      [-t TEMP_DIR] [-h] [-v]
                      dump

AppMemDumper v2.1.3
Author: Alexandre D'Hondt

This tool automates the research of some artifacts for forensics purpose in
 memory dumps based upon Volatility for a series of common Windows applications.

It can also open multiple archive formats (it uses pyunpack). In case of an
 archive, the tool will extract all its files to a temporary directory and then
 try to open each file as a memory dump.

positional arguments:
  dump                  memory dump file path

optional arguments:
  -a APPS               comma-separated list of integers designating applications to be parsed (default: *)
                         Currently supported: 
                          [0] AdobeReader
                          [1] Clipboard*
                          [2] CriticalProcessesInfo*
                          [3] DumpInfo*
                          [4] Firefox
                          [5] FoxitReader
                          [6] InternetExplorer
                          [7] KeePass
                          [8] MSPaint
                          [9] MediaPlayerClassic
                          [10] Mimikatz*
                          [11] Notepad
                          [12] OpenOffice
                          [13] PDFLite
                          [14] SumatraPDF
                          [15] TrueCrypt
                          [16] UserHashes*
                          [17] Wordpad
                         (*: general-purpose dumper) (default: all)
  -d DUMP_DIR, --dump-dir DUMP_DIR
                        dump directory (default: ./files/) (default: files)
  -f, --force           force profile search, do not use cached profile (default: false) (default: False)
  -p PLUGINS_DIR, --plugins-dir PLUGINS_DIR
                        path to custom plugins directory (default: none) (default: None)
  -t TEMP_DIR, --temp-dir TEMP_DIR
                        temporary directory for decompressed images (default: ./.temp/) (default: .temp)

extra arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose mode (default: False)

Usage examples:
  python app-mem-dumper memory.dmp
  python app-mem-dumper my-dumps.tar.gz
  python app-mem-dumper dump.raw -a 0,1 -f

 ```
 
2. Example of output

 ```session
 $ app-mem-dumper memory.dump -v -p plugins
 [appmemdumper] XX:XX:XX [DEBUG] Attempting to decompress 'memory.dump'...
 [appmemdumper] XX:XX:XX [DEBUG] Not an archive, continuing...
 [appmemdumper] XX:XX:XX [DEBUG] Setting output directory to 'files/memory.dump'...
 [appmemdumper] XX:XX:XX [INFO] Opening dump file 'memory.dump'...
 [appmemdumper] XX:XX:XX [INFO] Getting profile...
 [appmemdumper] XX:XX:XX [INFO] Getting processes...
 [appmemdumper] XX:XX:XX [DEBUG] > Executing command 'pslist'...
 [appmemdumper] XX:XX:XX [DEBUG] Found       : mspaint.exe
 [appmemdumper] XX:XX:XX [DEBUG] Not handled : audiodg.exe, csrss.exe, dllhost.exe, [...]
 [appmemdumper] XX:XX:XX [DEBUG] Profile: Win7SP0x86
 [appmemdumper] XX:XX:XX [INFO] Processing dumper 'dumpinfo'...
 [appmemdumper] XX:XX:XX [INFO] Processing dumper 'mspaint'...
 [appmemdumper] XX:XX:XX [DEBUG] Dumping for PID XXXX
 [appmemdumper] XX:XX:XX [DEBUG] > Calling command 'memdump'...
 [appmemdumper] XX:XX:XX [DEBUG] >> volatility --plugins=/path/to/plugins --file=[...]
 [appmemdumper] XX:XX:XX [INFO] > /path/to/files/memory.dump/mspaint-2640-memdump.data
 [appmemdumper] XX:XX:XX [WARNING] 
 The following applies to collected objects of:
 - mspaint
 
 Raw data (.data files) requires manual handling ;
 Follow this procedure:
  1. Open the collected resources with Gimp
  2. Set the width and height to the expected screen resolution
  3. Set another color palette than 'RVB'
 Restart this procedure by setting other parameters for width|height|palette.

 ```


## Issues management

Please [open an Issue](https://github.com/dhondta/appmemdumper/issues/new) if you want to contribute or submit suggestions. 

The *labels* usage convention is as follows :
 - General question: *question*
 - Suggestion: *help wanted*
 - Bug/exception/problem: *bug*
 - Improvement/contribution: *enhancement* ; NB: please precise if you are motivated and able to contribute

If you want to build and submit new dumpers, please open a Pull Request.
