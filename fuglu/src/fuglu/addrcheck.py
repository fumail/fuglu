import re
import logging


# Singleton implementation for Addrcheck
class Addrcheck(object):
    """
    Singleton implementation for Addrcheck. Note it is important not
    to initialise "self._method" by creating a "__init__" function
    since this would be called whenever asking for the singleton...
    (Addrcheck() would call __init__).
    """
    __instance = None

    def __new__(cls):
        """
        Returns Singleton of Addrcheck (create if not yet existing)

        Returns:
            (Addrcheck) The singleton of Addrcheck
        """
        if Addrcheck.__instance is None:
            Addrcheck.__instance = object.__new__(cls)
            Addrcheck.__instance.set("Default")
        return Addrcheck.__instance

    def set(self, name):
        """
        Sets method to be used in valid - function to validate an address
        Args:
            name (String): String with name of validator
        """
        if name == "Default":
            self._method = Default()
        elif name == "LazyLocalPart":
            self._method = LazyLocalPart()
        else:
            logger = logging.getLogger("fuglu.Addrcheck")
            logger.warning("Mail address check \"%s\" not valid, using default..."%name)
            self._method = Default()

    def valid(self, address):
        """

        Args:
            address (String): Address to be checked

        Returns:
            (Boolean) True if address is valid using internal validation method

        """
        return self._method(address)


class Addrcheckint(object):
    """
    Functor interface for method called by Addrcheck
    """
    def __init__(self):
        pass
    def __call__(self, mailAddress):
        raise NotImplemented

class Default(Addrcheckint):
    """
    Default implementation (and backward compatible) which does not allow more than one '@'
    """
    def __init__(self):
        super(Default, self).__init__()
    def __call__(self,mailAddress):
        leg =  (mailAddress !='' and  (   re.match(r"[^@]+@[^@]+$", mailAddress)))
        return leg

class LazyLocalPart(Addrcheckint):
    """
    Allows '@' in local part if quoted
    """
    def __init__(self):
        super(LazyLocalPart, self).__init__()
    def __call__(self,mailAddress):
        leg = ( mailAddress !='' and  (      re.match(r"[^@]+@[^@]+$", mailAddress)
                                          or re.match(r"^\"[\x00-\x7f]+\"@[^@]+$", mailAddress) ))
        return leg

