import logging
import logging.handlers
import logging.config
import fuglu.procpool

class logConfig(object,):
    """
    Conig class to easily distinguish logging configuration for lint and production (from file)
    """
    def __init__(self,logQueue,lint=False,logConfigFile=None):
        """
        Setup in lint mode of using a config file
        Args:
            lint (bool): enable lint mode which will print on the screen
            logConfigFile (): load configuration from config file
        """
        assert (lint or logConfigFile)
        assert not (lint and logConfigFile)

        self._logQueue = logQueue
        self._configFile = logConfigFile
        self._lintOutputLevel = logging.ERROR

        self._lint = lint
        if self._lint:
            self.configure = self._configure4lint
        elif self._configFile:
            self.configure = self._configure
        else:
            raise Exception("Not implemented!")

    @property
    def queue(self):
        return self._logQueue

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
        print("Print DEBUG: "+str(root.isEnabledFor(logging.DEBUG)))
        print("Print INFO: "+str(root.isEnabledFor(logging.INFO)))
        print("Print ERROR: "+str(root.isEnabledFor(logging.ERROR)))


def listener_process(configurer):
    """
    This is the listener process top-level loop: wait for logging events
    (LogRecords) on the queue and handle them, quit when you get a None for a
    LogRecord.

    Args:
        configurer (logConfig): instance lof logConfig class setting up logging on configure call

    Returns:

    """
    configurer.configure()
    root = logging.getLogger()
    root.info("Listener process started")
    while True:
        try:
            record = configurer.queue.get()
            if record is None:  # We send this as a sentinel to tell the listener to quit.
                break
            #print("listener_process: "+str(record))
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
        root.info("(%s) Queue handler already present in root logger" % name)
