#   Copyright 2009-2018 Oli Schacher
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
#
#
import logging
import socket
import threading
from fuglu.scansession import SessionHandler
import traceback
from multiprocessing.reduction import ForkingPickler
import StringIO

class ProtocolHandler(object):
    protoname = 'UNDEFINED'

    def __init__(self, socket, config):
        self.socket = socket
        self.config = config
        self.logger = logging.getLogger('fuglu.%s' % self.__class__.__name__)

    def get_suspect(self):
        return None

    def commitback(self, suspect):
        pass

    def defer(self, reason):
        pass

    def discard(self, reason):
        pass

    def reject(self, reason):
        pass

class BasicTCPServer(object):

    def __init__(self, controller, port=10125, address="127.0.0.1", protohandlerclass=None):
        if protohandlerclass == None:
            protohandlerclass = ProtocolHandler
        self.protohandlerclass = protohandlerclass
        self.logger = logging.getLogger("fuglu.incoming.%s" % (port))
        self.logger.debug('Starting incoming Server on Port %s, protocol=%s' % (
            port, self.protohandlerclass.protoname))
        self.port = port
        self.controller = controller
        self.stayalive = True

        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception as e:
            self.logger.error(
                'Could not start incoming Server on port %s: %s' % (port, e))
            self.stayalive = False

    def shutdown(self):
        self.logger.info("TCP Server on port %s closing" % self.port)
        self.stayalive = False
        try:
            self._socket.shutdown(1)
            self._socket.close()
        except:
            pass

    def serve(self):
        controller = self.controller
        threadpool = self.controller.threadpool
        procpool = self.controller.procpool

        threading.currentThread().name = '%s Server on Port %s' % (
            self.protohandlerclass.protoname, self.port)

        self.logger.info('%s Server running on port %s' %
                         (self.protohandlerclass.protoname, self.port))

        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                nsd = self._socket.accept()
                sock,addr = nsd
                if not self.stayalive:
                    break
                ph = self.protohandlerclass(sock, controller.config)
                engine = SessionHandler(
                    ph, controller.config, controller.prependers, controller.plugins, controller.appenders)
                self.logger.debug('Incoming connection from %s' % str(addr))
                if threadpool:
                    # this will block if queue is full
                    threadpool.add_task(engine)
                elif procpool:
                    # in multi processing, the other process manages configs and plugins itself, we only pass the minimum required information:
                    # a pickled version of the socket (this is no longer required in python 3.4, but in python 2 the multiprocessing queue can not handle sockets
                    # see https://stackoverflow.com/questions/36370724/python-passing-a-tcp-socket-object-to-a-multiprocessing-queue
                    handler_classname = self.protohandlerclass.__name__
                    handler_modulename = self.protohandlerclass.__module__
                    task = forking_dumps(sock),handler_modulename, handler_classname
                    procpool.add_task(task)
                else:
                    engine.handlesession()
            except Exception as e:
                exc = traceback.format_exc()
                self.logger.error(
                    'Exception in serve(): %s - %s' % (str(e), exc))


def forking_dumps(obj):
    """ Pickle a socket This is required to pass the socket in multiprocessing"""
    buf = StringIO.StringIO()
    ForkingPickler(buf).dump(obj)
    return buf.getvalue()