#   Copyright 2009-2016 Oli Schacher
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


# additional loggers
# source:
# http://stackoverflow.com/questions/1407474/does-python-logging-handlers-rotatingfilehandler-allow-creation-of-a-group-writa

import logging
import os


class GroupReadableRotatingFileHandler(logging.handlers.RotatingFileHandler):

    def _open(self):
        prevumask = os.umask(0o137)
        rtv = logging.handlers.RotatingFileHandler._open(self)
        os.umask(prevumask)
        return rtv


class GroupWritableRotatingFileHandler(logging.handlers.RotatingFileHandler):

    def _open(self):
        prevumask = os.umask(0o117)
        rtv = logging.handlers.RotatingFileHandler._open(self)
        os.umask(prevumask)
        return rtv


class GroupReadableTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):

    def _open(self):
        prevumask = os.umask(0o137)
        rtv = logging.handlers.TimedRotatingFileHandler._open(self)
        os.umask(prevumask)
        return rtv


class GroupWritableTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):

    def _open(self):
        prevumask = os.umask(0o117)
        rtv = logging.handlers.TimedRotatingFileHandler._open(self)
        os.umask(prevumask)
        return rtv
