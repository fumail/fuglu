#   Copyright 2009-2017 Oli Schacher
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
import multiprocessing
import multiprocessing.queues

from fuglu.scansession import SessionHandler
import fuglu.core
import logging
import traceback
import importlib
import pickle

class ProcManager(object):
    def __init__(self, numprocs = None, queuesize=100, config = None):
        self.config = config
        self.numprocs = numprocs
        self.workers = []
        self.queuesize = queuesize
        self.tasks = multiprocessing.queues.Queue(queuesize)

        self.logger = logging.getLogger('%s.procpool' % __package__)
        self._stayalive = True
        self.name = 'ProcessPool'
        self.start()

    @property
    def stayalive(self):
        return self._stayalive

    @stayalive.setter
    def stayalive(self, value):
        # procpool is shut down -> send poison pill to workers
        if self._stayalive and not value:
            self._stayalive = False
            self._send_poison_pills()
        self._stayalive = value

    def _send_poison_pills(self):
        """flood the queue with poison pills to tell all workers to shut down"""
        for _ in range(len(self.workers)):
            self.tasks.put_nowait(None)

    def add_task(self, session):
        if self._stayalive:
            self.tasks.put(session)

    def start(self):
        for i in range(self.numprocs):
            worker = multiprocessing.Process(target=fuglu_process_worker, args=(self.tasks,self.config))
            worker.start()
            self.workers.append(worker)

    def shutdown(self):
        self. stayalive = False


def fuglu_process_worker(queue, config):
    logging.basicConfig(level=logging.DEBUG)

    logger = logging.getLogger('fuglu.process')
    logger.debug("Child ready")

    # load config and plugins
    controller = fuglu.core.MainController(config)
    controller.load_extensions()
    controller.load_plugins()
    prependers = controller.prependers
    plugins = controller.plugins
    appenders = controller.appenders

    try:
        while True:
            task = queue.get()
            if task is None: # poison pill
                logger.debug("Child process received poison pill - shut down")
                return
            pickled_socket, handler_modulename, handler_classname = task
            sock = pickle.loads(pickled_socket)
            handler_class = getattr(importlib.import_module(handler_modulename), handler_classname)
            handler_instance = handler_class(sock, config)
            handler = SessionHandler(handler_instance, config,prependers, plugins, appenders)
            handler.handlesession()
    except:
        trb = traceback.format_exc()
        logger.error("Exception in child process: %s"%trb)


