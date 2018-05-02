import re

class MailAddrLegCheckerInterface(object):
    def __init__(self):
        pass
    def __call__(self,mailAddress):
        raise NotImplemented

class Default(MailAddrLegCheckerInterface):
    """
    Default implementation (and backward compatible) which does not allow more than one '@'
    """
    def __init__(self):
        super(Default, self).__init__()
    def __call__(self,mailAddress):
        leg =  mailAddress !='' and  (   re.match(r"[^@]+@[^@]+$", mailAddress))
        return leg

class LazyQuotedLocalPart(MailAddrLegCheckerInterface):
    """
    Allows '@' in local part if quoted
    """
    def __init__(self):
        super(LazyQuotedLocalPart, self).__init__()
    def __call__(self,mailAddress):
        leg =  mailAddress !='' and  (   re.match(r"[^@]+@[^@]+$", mailAddress)
                                      or re.match(r"^\"[\x00-\x7f]+\"@[^@]+$", mailAddress)
                                      or re.match(r"^\'[\x00-\x7f]+\'@[^@]+$", mailAddress) )
        return leg

