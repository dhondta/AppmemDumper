[![Build Status](https://travis-ci.org/dhondta/AppmemDumper.svg?branch=master)](https://travis-ci.org/dhondta/AppmemDumper)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.804958.svg)](https://doi.org/10.5281/zenodo.804958)


## Table of Contents

   * [Introduction](#introduction)
   * [Design Principles](#design-principles)
   * [System Requirements](#system-requirements)
   * [Installation](#installation)
   * [Quick Start](#quick-start)
   * [Issues management](#issues-management)


## Introduction

This self-contained tool automates the research of some artifacts for forensics purpose in memory dumps based upon Volatility for a series of common Windows applications.

It can also open multiple archive formats. In case of an archive, the tool will extract all its files to a temporary directory and then try to open each file as a memory dump (except files named README or README.md).


## Design principles:

- Maximum use of Python-builtin modules.
- For non-standard imports, trigger exit if not installed and display the command for installing these.
- No modularity (principle of self-contained tool) so that it can simply be copied in /usr/bin with dependencies other thant the non-standard imports.


## System Requirements

This framework was tested on an Ubuntu 16.04 with Python 2.7.

Its Python logic only uses standard built-in modules except `pyunpack`. It makes calls to Volatility and Foremost, thus requiring them.


## Installation

1. Clone this repository

 ```session
 $ git clone https://github.com/dhondta/appmemdumper.git
 ```
 
 > **Behind a proxy ?**
 > 
 > Setting: `git config --global http.proxy http://[user]:[pwd]@[host]:[port]`
 > 
 > Unsetting: `git config --global --unset http.proxy`
 > 
 > Getting: `git config --global --get http.proxy`

2. Install system requirements

 ```session
 $ sudo apt-get install volatility
 $ sudo apt-get install foremost
 ```

 > **Behind a proxy ?**
 > 
 > Do not forget to configure your Network system settings (or manually edit `/etc/apt/apt.conf`).
 
3. Install Python requirements

 ```session
 $ sudo pip install pyunpack
 ```

 > **Behind a proxy ?**
 > 
 > Do not forget to add option `--proxy=http://[user]:[pwd]@[host]:[port]` to your pip command.
 
4. [Facultative] Copy the Python script to your `bin` folder

 ```session
 $ chmod a+x appmemdumper.py
 $ sudo cp appmemdumper.py /usr/bin/appmemdumper
 ```


## Quick Start

1. Help

 ```session
 $ ./appmemdumper.py -h
 
 usage: appmemdumper [-h] [-a APPS] [-d DUMP_DIR] [-f] [-p PLUGINS]
                    [-t TEMP_DIR] [-v]
                    dump

 Appmemdumper v1.0
 [...]

 positional arguments:
   dump         memory dump file path

 optional arguments:
   -h, --help   show this help message and exit
   -a APPS      comma-separated list of integers designating applications to be parsed (default: *)
                 Currently supported: 
                  [0] adobereader
                  [1] dumpinfo*
                  [2] firefox
                  [3] foxitreader
                  [4] internetexplorer
                  [5] keepass
                  [6] mediaplayerclassic
                  [7] mspaint
                  [8] notepad
                  [9] openoffice
                  [10] pdflite
                  [11] sumatrapdf
                  [12] truecrypt
                  [13] userhashes*
                  [14] wordpad
                 (*: general-purpose dumper)
   -d DUMP_DIR  dump directory (default: ./files/)
   -f           force profile search, do not use cached profile (default: false)
   -p PLUGINS   path to the custom plugins directory (default: none)
   -t TEMP_DIR  temporary directory for decompressed images (default: ./.temp/)
   -v           verbose mode (default: false)

 Usage examples:
   python appmemdumper memory.dmp
   python appmemdumper my-dumps.tar.gz
   python appmemdumper dump.raw -a 0,1 -f

 Print documentation:
 - stdout: pydoc appmemdumper
 - html  : pydoc -w appmemdumper
 
 ```
 
2. Example of output

 ```session
 $ ./appmemdumper.py memory.dump -v -p plugins
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
