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
import threading
import time
try:
    import queue
except ImportError:
    import Queue as queue
import logging


class ThreadPool(threading.Thread):

    def __init__(self, minthreads=1, maxthreads=20, queuesize=100):
        self.workers = []
        self.queuesize = queuesize
        self.tasks = queue.Queue(queuesize)
        self.minthreads = minthreads
        self.maxthreads = maxthreads
        assert self.minthreads > 0
        assert self.maxthreads > self.minthreads

        self.logger = logging.getLogger('fuglu.threadpool')
        self.threadlistlock = threading.Lock()
        self.checkinterval = 10
        self.threadcounter = 0
        self._stayalive = True
        self.laststats = 0
        self.statinverval = 60
        threading.Thread.__init__(self)
        self.name = 'Threadpool'
        self.daemon = False
        self.start()

    @property
    def stayalive(self):
        return self._stayalive

    @stayalive.setter
    def stayalive(self, value):
        # threadpool is shut down -> send poison pill to workers
        if self._stayalive and not value:
            self._stayalive = False
            self._send_poison_pills()
        self._stayalive = value

    def _send_poison_pills(self):
        """flood the queue with poison pills to tell all workers to shut down"""
        for _ in range(self.maxthreads):
            self.tasks.put_nowait(None)

    def add_task(self, session):
        if self._stayalive:
            self.tasks.put(session)

    def get_task(self):
        if self._stayalive:
            return self.tasks.get(True)
        else:
            return None

    def run(self):
        self.logger.debug('Threadpool initializing. minthreads=%s maxthreads=%s maxqueue=%s checkinterval=%s' % (
            self.minthreads, self.maxthreads, self.queuesize, self.checkinterval))

        while self._stayalive:
            curthreads = self.workers
            numthreads = len(curthreads)

            # check the minimum boundary
            requiredminthreads = self.minthreads
            if numthreads < requiredminthreads:
                diff = requiredminthreads - numthreads
                self._add_worker(diff)
                continue

            # check the maximum boundary
            if numthreads > self.maxthreads:
                diff = numthreads - self.maxthreads
                self._remove_worker(diff)
                continue

            changed = False
            # ok, we are within the boundaries, now check if we can dynamically
            # adapt something
            queuesize = self.tasks.qsize()

            # if there are more tasks than current number of threads, we try to
            # increase
            workload = float(queuesize) / float(numthreads)

            if workload > 1 and numthreads < self.maxthreads:
                self._add_worker()
                numthreads += 1
                changed = True

            if workload < 1 and numthreads > self.minthreads:
                self._remove_worker()
                numthreads -= 1
                changed = True

            # log current stats
            if changed or time.time() - self.laststats > self.statinverval:
                workerlist = "\n%s" % '\n'.join(map(repr, self.workers))
                self.logger.debug('queuesize=%s workload=%.2f workers=%s workerlist=%s' % (
                    queuesize, workload, numthreads, workerlist))
                self.laststats = time.time()

            time.sleep(self.checkinterval)
        for worker in self.workers:
            worker.stayalive = False
        del self.workers
        self.logger.info('Threadpool shut down')

    def _remove_worker(self, num=1):
        self.logger.debug('Removing %s workerthread(s)' % num)
        for bla in range(0, num):
            worker = self.workers[0]
            worker.stayalive = False
            del self.workers[0]

    def _add_worker(self, num=1):
        self.logger.debug('Adding %s workerthread(s)' % num)
        for bla in range(0, num):
            self.threadcounter += 1
            worker = Worker("[%s]" % self.threadcounter, self)
            self.workers.append(worker)
            worker.start()


class Worker(threading.Thread):

    def __init__(self, workerid, pool):
        threading.Thread.__init__(self, name='Pool worker %s' % workerid)
        self.workerid = workerid
        self.birth = time.time()
        self.pool = pool
        self.stayalive = True
        self.logger = logging.getLogger('fuglu.threads.worker.%s' % workerid)
        self.logger.debug('thread init')
        self.noisy = False
        self.setDaemon(False)
        self.threadinfo = 'created'

    def __repr__(self):
        return "%s: %s" % (self.workerid, self.threadinfo)

    def run(self):
        self.logger.debug('thread start')

        while self.stayalive:
            self.threadinfo = 'waiting for task'
            if self.noisy:
                self.logger.debug('Getting new task...')
            sesshandler = self.pool.get_task()
            if sesshandler == None:  # poison pill -> shut down
                if self.noisy:
                    self.logger.debug("got a poison pill .. good bye world")
                self.stayalive = False
                continue

            if self.noisy:
                self.logger.debug('Doing work')
            try:
                sesshandler.handlesession(self)
            except Exception as e:
                self.logger.error('Unhandled Exception : %s' % e)
            self.threadinfo = 'task completed'

        self.threadinfo = 'ending'
        self.logger.debug('thread end')
