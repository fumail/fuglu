import sys
import logging

try:
    import chardet
    chardetAvailable = True
except ImportError:
    chardetAvailable = False


def try_encoding(u_inputstring,encoding="utf-8"):
    """Try to encode a unicode string

    Args:
        u_inputstring (unicode/str):
        encoding (str): target encoding type

    Returns:
        byte-string
    """

    logger = logging.getLogger("fuglu.encoding.try_encoding")
    try:
        return u_inputstring.encode(encoding,"strict")
    except UnicodeEncodeError as e:
        logger.error("Encoding error!")
        logger.exception(e)
        raise e


def try_decoding(b_inputstring,encodingGuess="utf-8"):
    """ Try to decode an encoded string

    Args:
        b_inputstring (str/bytes): input byte string
        encodingGuess (str): guess for encoding used

    Returns:
        unicode string

    """
    u_outputstring = None
    logger = logging.getLogger("fuglu.encoding.try_decoding")
    try:
        u_outputstring = b_inputstring.decode(encodingGuess,"strict")
    except UnicodeDecodeError:
        logger.warning("found non %s encoding, try to detect encoding" % encodingGuess)
        if chardetAvailable:
            encoding = chardet.detect(b_inputstring)['encoding']
            logger.warning("encoding estimated as %s" % encoding)
            try:
                u_outputstring = b_inputstring.decode(encoding,"strict")
            except Exception as e:
                raise e
        else:
            logger.warning("module chardet not available -> skip autodetect")
            raise UnicodeDecodeError
    except Exception as e:
        logger.error("decoding failed!")
        logger.exception(e)
        raise e

    return u_outputstring

def force_uString(inputstring):
    """Try to enforce a unicode string
    
    Args:
        inputstring (str or unicode): input string to be checked

    Returns:
        unicode string

    """

    if sys.version_info > (3,):
        # Python 3 and larger
        # the basic "str" type is unicode
        if isinstance(inputstring,str):
            return inputstring
        else:
            return try_decoding(inputstring)
    else:
        # Python 2.x
        # the basic "str" type is bytes, unicode
        # has its own type "unicode"
        if isinstance(inputstring,unicode):
            return inputstring
        else:
            return try_decoding(inputstring)


def force_bString(inputstring,encoding="utf-8",checkEncoding=False):
    """Try to enforce a string of bytes

    Args:
        inputstring (unicode or byte-string): input string

    Keyword Args:
        encoding (str): encoding type in case of encoding needed
        checkEncoding (bool): if input string is encoded, check type

    Returns: encoded byte string

    """

    if sys.version_info > (3,):
        # Python 3 and larger
        # the basic "str" type is unicode
        if not isinstance(inputstring,str):
            # string is already a byte string
            # since basic string type is unicode
            b_outString = inputstring
        else:
            # encode
            b_outString = try_encoding(inputstring,encoding)
    else:
        # Python 2.x
        # the basic "str" type is bytes, unicode
        # has its own type "unicode"
        if not isinstance(inputstring,unicode):
            # string is already a byte string
            b_outString = inputstring
        else:
            # encode
            b_outString = try_encoding(inputstring,encoding)

    if checkEncoding:
        # re-encode to make sure it matches input encoding
        return try_encoding(try_decoding(b_outString,encodingGuess=encoding),encoding=encoding)
    else:
        return b_outString

def forceBytesFromChar(chars_iteratable):
    if isinstance(chars_iteratable,bytes):
        return chars_iteratable
    elif isinstance(chars_iteratable,str):
        return bytes([ord(x) for x in chars_iteratable])
    else:
        raise AttributeError

def forceCharFromBytes(bytes_iteratable):
    if isinstance(bytes_iteratable,str):
        return bytes_iteratable
    elif isinstance(bytes_iteratable,bytes):
        return "".join([chr(x) for x in bytes_iteratable])
    else:
        raise AttributeError
