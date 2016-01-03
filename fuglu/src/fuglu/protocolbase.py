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
#
#
import logging
import socket
import threading
from fuglu.scansession import SessionHandler
import traceback


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
        # disable to debug...
        use_multithreading = True
        controller = self.controller
        threading.currentThread().name = '%s Server on Port %s' % (
            self.protohandlerclass.protoname, self.port)

        self.logger.info('%s Server running on port %s' %
                         (self.protohandlerclass.protoname, self.port))
        if use_multithreading:
            threadpool = self.controller.threadpool
        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                nsd = self._socket.accept()
                if not self.stayalive:
                    break
                ph = self.protohandlerclass(nsd[0], controller.config)
                engine = SessionHandler(
                    ph, controller.config, controller.prependers, controller.plugins, controller.appenders)
                self.logger.debug('Incoming connection from %s' % str(nsd[1]))
                if use_multithreading:
                    # this will block if queue is full
                    threadpool.add_task(engine)
                else:
                    engine.handlesession()
            except Exception as e:
                exc = traceback.format_exc()
                self.logger.error(
                    'Exception in serve(): %s - %s' % (str(e), exc))
