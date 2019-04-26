#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging
from subprocess import CalledProcessError

from .template import DumperTemplate


__all__ = [
    "AdobeReader",
    "Firefox",
    "FoxitReader",
    "InternetExplorer",
    "KeePass",
    "MediaPlayerClassic",
    "MSPaint",
    "Notepad",
    "OpenOffice",
    "PDFLite",
    "SumatraPDF",
    "TrueCrypt",
    "Wordpad",
]
logger = logging.getLogger("main")


class AdobeReader(DumperTemplate):
    """
    Dumper for the well-known application Adobe Reader. It uses the 'run()'
     method of DumperTemplate to extract the memory of the process and carves PDF
     files on it with Foremost then removes the memory dump.
    """
    procnames = ["reader.exe", "AcroRd32.exe"]

    def run(self):
        """
        Executes the 'memdump' Volatility command (DumperTemplate), carves PDF
         files with Foremost then removes the process memory dump.
        """
        self.carve(self._memdump(verbose=False), ('pdf',), clean=True)


class Firefox(DumperTemplate):
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
            logger.warning("Firefox plugins are not built in Volatility ;"
                           " please ensure that you used the -p option to set"
                           " the path to custom plugins.")


class FoxitReader(AdobeReader):
    """
    Dumper for the common application Foxit Reader. It performs the same
     operations as AdobeReaderDumper.
    """
    procnames = ["FoxitReader.ex", "FoxitReader.exe"]


class InternetExplorer(DumperTemplate):
    """
    Dumper for the common application Microsoft Internet Explorer.
    """
    procnames = ["iexplore.exe"]
    re_patterns = [(r'function FindProxyForURL.{232}', 'txt', 'proxy-rules')]

    def run(self):
        """
        Executes some IExplorer-related Volatility command.
        """
        cmd = 'iehistory'
        self._dump_file(self.dump.call(cmd), cmd)
        self._memsearch(split_on_nullbyte=True)


class KeePass(DumperTemplate):
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
        Executes the 'memdump' Volatility command (DumperTemplate), retrieves
         some XML content, then executes the 'vaddump' Volatility command and
         finally gets the KeePass DB from the VAD nodes.
        """
        self._memsearch()
        self._vadsearch(include_pattern=True)


class MediaPlayerClassic(DumperTemplate):
    """
    Dumper for the common application Media Player Classic. It performs the same
     operations as MSPaintDumper.
    """
    procnames = ["mpc-hc.exe"]
    messages = DumperTemplate._predef_messages[0:1]

    def run(self):
        self._memdump()


class MSPaint(DumperTemplate):
    """
    Dumper for the well-known application Paint built in Microsoft Windows. It
     uses the 'run()' method of DumperTemplate to extract the memory of the
     process for further analysis using the 'memdump' Volatility command.
    """
    procnames = ["mspaint.exe"]
    messages = DumperTemplate._predef_messages[0:1]

    def run(self):
        self._memdump()


class Notepad(DumperTemplate):
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
            pid = self.dump.OutputParser(meta)['Process ID']
            if self.dump.config.PID == pid:
                self._dump_file(text, cmd)
                return
        logger.debug("Nothing found with 'editbox'")
        # Try 3: use 'vaddump' and search for patterns in VAD nodes
        self._vadsearch(reduce_text=True)


class OpenOffice(DumperTemplate):
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
        Executes the 'memdump' Volatility command (DumperTemplate) and retrieves
         OpenOffice documents.
        """
        self._memsearch()


class PDFLite(AdobeReader):
    """
    Dumper for the common application PDFLite. It performs the same operations
     as AdobeReaderDumper.
    """
    procnames = ["PDFlite.exe"]


class SumatraPDF(AdobeReader):
    """
    Dumper for the common application Sumatra PDF. It performs the same
     operations as AdobeReaderDumper.
    """
    procnames = ["SumatraPDF.exe"]


class TrueCrypt(DumperTemplate):
    """
    Dumper for the common application TrueCrypt.
    """
    procnames = ["TrueCrypt.exe"]

    def run(self):
        """
        Executes the 'memdump' Volatility command (DumperTemplate) and the
         TrueCrypt-related Volatility commands.
        """
        self._memdump()
        for cmd in ['truecryptmaster', 'truecryptpassphrase',
                    'truecryptsummary']:
            self._dump_file(self.dump.call(cmd), cmd)


class Wordpad(DumperTemplate):
    """
    Dumper for the well-known application Wordpad built in Microsoft Windows. It
     uses the 'run()' method of DumperTemplate to extract the memory of the
     process for further analysis using the 'memdump' Volatility command. It
     also uses the 'carve()' method of DumperTemplate to extract image resources
     and executes the 'vaddump' Volatility command for retrieving Virtual
     Address Descriptor (VAD) objects for later manual analysis.
    """
    procnames = ["wordpad.exe"]
    messages = DumperTemplate._predef_messages[0:2]

    def run(self):
        """
        Executes the 'memdump' Volatility command (DumperTemplate), carves files
         with Foremost then executes the 'editbox' Volatility command.
        """
        self.carve(self._memdump(verbose=False), ('jpg', 'png',), clean=True)
        # TODO: find patterns for searching into the VAD nodes
        # self._vaddump()
