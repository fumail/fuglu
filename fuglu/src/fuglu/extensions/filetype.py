# -*- coding: UTF-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This content has been extracted from attachment.py and refactored
#

import threading
import sys

MAGIC_AVAILABLE = 0
MAGIC_PYTHON_FILE = 1
MAGIC_PYTHON_MAGIC = 2

STATUS = "not loaded"
ENABLED = False

try:
    import magic

    # try to detect which magic version is installed
    # python-file/libmagic bindings (http://www.darwinsys.com/file/)
    if hasattr(magic, 'open'):
        MAGIC_AVAILABLE = MAGIC_PYTHON_FILE
    # python-magic (https://github.com/ahupp/python-magic)
    elif hasattr(magic, 'from_buffer'):
        MAGIC_AVAILABLE = MAGIC_PYTHON_MAGIC

    # unsupported version, for example 'filemagic'
    # https://github.com/aliles/filemagic
except ImportError:
    pass


STATUS = "available"
ENABLED = MAGIC_AVAILABLE > 0

class MIME_types_base(object):
    """
    Base class for mime file type magic
    """
    def __init__(self):
        self.magic = None

    def get_filetype(self,path):
        return None

    def get_buffertype(self,buffercontent):
        return None

    def available(self):
        """
        Return if there's a mime filetype module available to be used.

        All the implementations of this class should actually allocate
        something for self.magic and therefore it will not be None anymore. It
        would also be possible to check for "MAGIC_AVAILABLE > 0" but this would
        be a less object oriented approach...

        Returns:
            (bool) True if there's a file type module available to be used

        """
        return (self.magic is not None)

class Typemagic_MIME_pythonfile(MIME_types_base):
    """
    MIME file type magic using magic module python file magic

    python-file/libmagic bindings (http://www.darwinsys.com/file/
    """
    def __init__(self):
        super(Typemagic_MIME_pythonfile,self).__init__()
        ms = magic.open(magic.MAGIC_MIME)
        ms.load()
        self.magic = ms

    def get_filetype(self,path):
        return self.magic.file(path)

    def get_buffertype(self,buffercontent):
        return self.magic.buffer(buffercontent)

class Typemagic_MIME_pythonmagic(MIME_types_base):
    """
    MIME file type magic using magic module python magic

    python-magic (https://github.com/ahupp/python-magic)
    """
    def __init__(self):
        super(Typemagic_MIME_pythonmagic,self).__init__()
        self.magic = magic
    def get_filetype(self,path):
        return magic.from_file(path, mime=True)

    def get_buffertype(self,buffercontent):
        btype = magic.from_buffer(buffercontent, mime=True)
        if isinstance(btype, bytes) and sys.version_info > (3,):
            btype = btype.decode('UTF-8', 'ignore')
        return btype


class ThreadLocalMagic(threading.local):

    def __init__(self, **kw):

        self._magicversion = MAGIC_AVAILABLE

        if MAGIC_AVAILABLE == MAGIC_PYTHON_FILE:
            self._typemagic = Typemagic_MIME_pythonfile()
        elif MAGIC_AVAILABLE == MAGIC_PYTHON_MAGIC:
            self._typemagic = Typemagic_MIME_pythonmagic()
        else:
            self._typemagic = MIME_types_base()

    def __getattr__(self, name):
        """
        Passing all requests for attributes/methods to actual implementation

        Args:
            name (str): Name of attribute/method

        Returns:
            the answer fo the actual implementation

        """
        return getattr(self._typemagic, name)

    def lint(self):
        """
        Info about module printed on screen(lint)

        Returns:
            (bool) True if there's a mime type magic module available to be used
        """
        lint_string = "not available"
        if MAGIC_AVAILABLE == 0:
            if 'magic' in sys.modules:  # unsupported version
                print("The installed version of the magic module is not supported. Content/File type analysis only works with python-file from http://www.darwinsys.com/file/ or python-magic from https://github.com/ahupp/python-magic")
            else:
                print("Python libmagic bindings (python-file or python-magic) not available. No Content/File type analysis.")
            return False,lint_string
        elif MAGIC_AVAILABLE == MAGIC_PYTHON_FILE:
            print("Found python-file/libmagic bindings (http://www.darwinsys.com/file/)")
        elif MAGIC_AVAILABLE == MAGIC_PYTHON_MAGIC:
            print("Found python-magic (https://github.com/ahupp/python-magic)")
        return True, lint_string

filetype_handler = ThreadLocalMagic()

