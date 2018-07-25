# -*- coding: utf-8 -*-
#   Copyright 2009-2018 Fumail Project
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
    if u_inputstring is None:
        return None

    logger = logging.getLogger("fuglu.stringencode.try_encoding")
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
    Keyword Args:
        encodingGuess (str): guess for encoding used, default assume unicode

    Returns:
        unicode string

    """
    if b_inputstring is None:
        return None
    
    logger = logging.getLogger("fuglu.stringencode.try_decoding")
    try:
        u_outputstring = b_inputstring.decode(encodingGuess,"strict")
    except (UnicodeDecodeError, LookupError):
        logger.warning("found non %s encoding or encoding not found, try to detect encoding" % encodingGuess)
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
    except AttributeError as e:
        logger.debug("could not decode value, not of string type: %s: %s" % (type(b_inputstring), b_inputstring))
        logger.exception(e)
        raise e
        u_outputstring = b_inputstring
    except Exception as e:
        logger.error("decoding failed!")
        logger.exception(e)
        raise e

    return u_outputstring


def force_uString(inputstring,encodingGuess="utf-8"):
    """Try to enforce a unicode string
    
    Args:
        inputstring (str, unicode, list): input string or list of strings to be checked
    Keyword Args:
        encodingGuess (str): guess for encoding used, default assume unicode

    Returns: unicode string (or list with unicode strings)

    """
    if inputstring is None:
        return None
    elif isinstance(inputstring,list):
        return [force_uString(item) for item in inputstring]

    if sys.version_info > (3,):
        # Python 3 and larger
        # the basic "str" type is unicode
        if isinstance(inputstring,str):
            return inputstring
        else:
            return try_decoding(inputstring,encodingGuess)
    else:
        # Python 2.x
        # the basic "str" type is bytes, unicode
        # has its own type "unicode"
        if isinstance(inputstring,unicode):
            return inputstring
        else:
            return try_decoding(inputstring,encodingGuess)


def force_bString(inputstring,encoding="utf-8",checkEncoding=False):
    """Try to enforce a string of bytes

    Args:
        inputstring (unicode, str, list): string or list of strings
        encoding (str): encoding type in case of encoding needed
        checkEncoding (bool): if input string is encoded, check type

    Returns: encoded byte string (or list with endcoded strings)

    """
    if inputstring is None:
        return None
    elif isinstance(inputstring,list):
        return [force_bString(item) for item in inputstring]

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

def force_bfromc(chars_iteratable):
    """Python 2 like bytes from char for Python 3

    Implemented to have the same char-byte conversion in Python 3 as in Python 2
    for special applications. In general it is recommended to use the real
    str.encode() function for Python3

    Args:
        chars_iteratable (str or bytes): char-string to be byte-encoded

    Returns:
        bytes: a byte-string

    """
    if isinstance(chars_iteratable,bytes):
        return chars_iteratable
    elif isinstance(chars_iteratable,str):
        return bytes([ord(x) for x in chars_iteratable])
    else:
        raise AttributeError

def force_cfromb(bytes_iteratable):
    """Python 2 like chars from bytes for Python 3

    Implemented to have the same byte-char conversion in Python 3 as in Python 2
    for special applications. In general it is recommended to use the real
    bytes.decode() function for Python3

    Args:
        bytes_iteratable (): byte-string

    Returns:
        str: chr - string

    """
    if isinstance(bytes_iteratable,str):
        return bytes_iteratable
    elif isinstance(bytes_iteratable,bytes):
        return "".join([chr(x) for x in bytes_iteratable])
    else:
        raise AttributeError
