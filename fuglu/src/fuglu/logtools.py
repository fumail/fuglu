import logging
import logging.handlers
import logging.config
import fuglu.procpool
import multiprocessing

def logFactoryProcess(listenerQueue,logQueue):
    """
    This process is responsible for creating the logger listener for the given queue.
    This Listener process is responsible for actually handling all the log messages in the queue.

    You might ask why this is a separate process. This log-implementation satisfies two constraints:
    - it has to work in multiprocessing mode
    - it has to work with TimedRotatingFileHandler
    - it has to at least be possible to change the debug level down to DEBUG

    Even in multiprocessing the subprocess inherits a lot of things from its father process at creation time.
    Using the logging module this can create quite weird effects. Withoug any change, using a TimedRotatingFileHandler
    most processes might still write to the old (archived) log file while the process that actually rotated the file
    and its threads will write to the new one.
    If the separate log process is created directly as a child of the main process is it not possible to recreate the
    log process later to take into account a new configuration, even if using a config server listener. The messages
    received from other processes will not necessarily apply the correct debug level if this has been changed.

    The only "clean" solution found so far is to always create the logging process from a clean process which does not
    have any logging structure stored yet. Therefore, the logFactoryProcess is created at the very beginning and it
    can produce new clean logging processes later that will properly setup with all propagation and level changes.

    Args:
        listenerQueue (multiprocessing.Queue): Queue where the logFactoryProcess will receive a configuration for
                                               which a new logging process will be created replacint the old one
        logQueue (multiprocessing.Queue): The queue where log messages will be sent, handled finally by the logging
                                          process

    """
    loggerProcess = None
    while True:
        try:
            logConfig = listenerQueue.get()

            # if existing stop last logger process
            if loggerProcess:
                # try to close the old logger
                try:
                    logQueue.put_nowait(None)
                    loggerProcess.join(10) # wait 10 seconds max
                except Exception:
                    loggerProcess.terminate()
                finally:
                    loggerProcess = None

            if logConfig is None:  # We send this as a sentinel to tell the listener to quit.
                break

            # create new logger process
            loggerProcess = multiprocessing.Process(target=listener_process, args=(logConfig,logQueue))
            loggerProcess.daemon = True
            loggerProcess.start()

        except KeyboardInterrupt:
            print("Listener process received KeyboardInterrupt")
            break
        except Exception:
            import sys, traceback
            print('Whoops! Problem:', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


class logConfig(object):
    """
    Conig class to easily distinguish logging configuration for lint and production (from file)
    """
    def __init__(self,lint=False,logConfigFile=None):
        """
        Setup in lint mode of using a config file
        Args:
            lint (bool): enable lint mode which will print on the screen
            logConfigFile (): load configuration from config file
        """
        assert (lint or logConfigFile)
        assert not (lint and logConfigFile)

        self._configFile = logConfigFile
        self._lintOutputLevel = logging.ERROR

        self._lint = lint
        if self._lint:
            self.configure = self._configure4lint
        elif self._configFile:
            self.configure = self._configure
        else:
            raise Exception("Not implemented!")

    def _configure4lint(self):
        """
        Configure for lint mode (output is on the screen, level is debug)
        """
        root = logging.getLogger()
        console = logging.StreamHandler()
        console.setLevel(self._lintOutputLevel)
        # set a format which is simpler for console use
        formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        root.addHandler(console)

    def _configure(self):
        """
        Configure logging using log configuration file
        """
        logging.config.fileConfig(self._configFile)
        root = logging.getLogger()


def listener_process(configurer,queue):
    """
    This is the listener process top-level loop: wait for logging events
    (LogRecords) on the queue and handle them, quit when you get a None for a
    LogRecord.

    Args:
        configurer (logConfig): instance lof logConfig class setting up logging on configure call
        queue (multiprocessing.Queue): The queue where log messages will be received and processed by this same process
    """
    configurer.configure()
    root = logging.getLogger()
    root.info("Listener process started")
    logLogger = logging.getLogger("LogListener")
    if logLogger.propagate:
        root.info("No special Log-logger")
        logLogger = None
    else:
        root.info("Using special LogLogger")

    while True:
        try:
            record = queue.get()
            if logLogger:
                logLogger.debug("Approx queue size: %u, received record to process -> %s"%(queue.qsize(),record))

            if queue.full():
                root.error("QUEUE IS FULL!!!")
                if logLogger:
                    logLogger.error("QUEUE IS FULL!!!")

            if record is None:  # We send this as a sentinel to tell the listener to quit.
                break
            logger = logging.getLogger(record.name)

            # check if this record should be logged or not...
            # the filter function should detect if the level is sufficient, but somehow it fails
            # so the check has to be done manually
            if logger.filter(record) and record.levelno >= logger.getEffectiveLevel():
                logger.handle(record)
        except KeyboardInterrupt:
            print("Listener process received KeyboardInterrupt")
            break
        except Exception:
            import sys, traceback
            print('Whoops! Problem:', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    root.info("Listener process stopped")


def client_configurer(queue):
    """
    The client configuration is done at the start of the worker process run.
    Note that on Windows you can't rely on fork semantics, so each process
    will run the logging configuration code when it starts.

    Args:
        queue (multiprocessing.Queue): queue where to send log messages

    """
    root = logging.getLogger()

    numRootHandlers = len(root.handlers)
    name = fuglu.procpool.createPIDinfo()

    if numRootHandlers == 0:
        h = logging.handlers.QueueHandler(queue)  # Just the one handler needed
        root.addHandler(h)
        # send all messages
        root.setLevel(logging.DEBUG)
        root.info("(%s) Queue handler added to root logger" % name)
    else:
        # on linux config is taken from father process automatically
        root.info("(%s) Root already has a handler -> not adding Queue handler" % name)
