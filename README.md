[![PyPi](https://img.shields.io/pypi/v/appmemdumper.svg)](https://pypi.python.org/pypi/appmemdumper/)
[![Build Status](https://travis-ci.org/dhondta/AppmemDumper.svg?branch=master)](https://travis-ci.org/dhondta/AppmemDumper)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.804958.svg)](https://doi.org/10.5281/zenodo.804958)
[![Python Versions](https://img.shields.io/pypi/pyversions/appmemdumper.svg)](https://pypi.python.org/pypi/appmemdumper/)
[![Requirements Status](https://requires.io/github/dhondta/AppmemDumper/requirements.svg?branch=master)](https://requires.io/github/dhondta/AppmemDumper/requirements/?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/dhondta/AppmemDumper/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/dhondta/AppmemDumper?targetFile=requirements.txt)
[![License](https://img.shields.io/pypi/l/appmemdumper.svg)](https://pypi.python.org/pypi/appmemdumper/)


## Introduction

This tool automates the research of some artifacts for forensics purpose in memory dumps based upon [Volatility](https://github.com/volatilityfoundation/volatility/) for a series of common Windows applications. It is aimed to facilitate triage while addressing multiple forensics images.

It can also open multiple archive formats. In case of an archive, the tool will extract all its files to a temporary directory and then try to open each file as a memory dump (except files named `README` or `README.md`).


## System Requirements

This framework was tested on an Ubuntu 18.04 with Python 2.7. It relies on Foremost and Volatility

```sh
$ sudo apt-get install foremost
$ git clone https://github.com/volatilityfoundation/volatility /tmp/vol-setup
$ cd /tmp/vol-setup && sudo python setup.py install
```

## Setup

```sh
$ pip install appmemdumper
```

> **Behind a proxy ?**
> 
> Do not forget to add option `--proxy=http://[user]:[pwd]@[host]:[port]` to your pip command.


## Quick Start

1. Help

 ```sh
$ app-mem-dumper --help
AppMemDumper 2.4.3
Author   : Alexandre D'Hondt
Copyright: © 2020 A. D'Hondt
License  : GNU Affero General Public License v3.0

This tool automates the research of some artifacts for forensics purpose in memory dumps based upon Volatility for a
 series of common Windows applications.

It can also open multiple archive formats (it uses pyunpack). In case of an archive, the tool will extract all its files
 to a temporary directory and then try to open each file as a memory dump.

usage: ./app-mem-dumper [-a APPS] [-s SYST] [-f] [-p PLUGINS]
                        [--profile PROFILE] [-d DUMP_DIR] [-t TEMP_DIR] [-u]
                        [-h] [--help] [-v]
                        dump

positional arguments:
  dump  memory dump file path


application/system dumpers:
  -a APPS  comma-separated list of integers designating applications to be parsed
            Currently supported: 

             [0] AdobeReader             [8] Notepad
             [1] Chrome                  [9] OpenOffice
             [2] Firefox                 [10] PDFLite
             [3] FoxitReader             [11] SumatraPDF
             [4] InternetExplorer        [12] Thunderbird
             [5] KeePass                 [13] TrueCrypt
             [6] MSPaint                 [14] Wordpad
             [7] MediaPlayerClassic    
            (default: all)
  -s SYST  comma-separated list of integers designating system items to be parsed
            Currently supported: 

             [0] Autoruns                [9] Malfind
             [1] Clipboard               [10] Mimikatz
             [2] CommandLines            [11] NetworkConnections
             [3] CriticalProcessesInfo   [12] ProcessesInfo
             [4] Devices                 [13] Registry
             [5] DumpInfo                [14] Timeline
             [6] FilesList               [15] UserActivities
             [7] Kernel                  [16] UserHashes
             [8] LsaSecrets            
            (default: none)

volatility options:
  -f, --force           force profile search, do not use cached profile (default: False)
  -p PLUGINS, --plugins-dir PLUGINS
                        path to custom plugins (default: None)
  --profile PROFILE     force Volatility profile (default: None)
                         NB: has the precedence on -f/--force

output options:
  -d DUMP_DIR, --dump-dir DUMP_DIR
                        dump directory (default: files)
  -t TEMP_DIR, --temp-dir TEMP_DIR
                        temporary directory for decompressed images (default: .temp)
  -u, --update          update previous dump directories (default: False)

extra arguments:
  -h             show usage message and exit
  --help         show this help message and exit
  -v, --verbose  verbose mode (default: False)

Usage examples:
  ./app-mem-dumper memory.dmp
  ./app-mem-dumper my-dumps.tar.gz
  ./app-mem-dumper dumps.zip -a none -s all
  ./app-mem-dumper dump.raw -a 1,2,4 -f
  ./app-mem-dumper dump.mem -a 0,3,10,11 -s 0
  ./app-mem-dumper dump.raw -v --profile Win7SP1x86

 ```
 
2. Example of output

 ```sh
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

