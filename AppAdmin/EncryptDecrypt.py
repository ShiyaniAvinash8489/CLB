"""
**************
    Packages 
**************
"""

# Cryptography
from unittest import result
from cryptography.fernet import Fernet

# Base64
import base64

# Logging
import logging

# Trance Back
import traceback

# Json & ASt
import json
import ast

# Date & Time
import datetime

# OrderedDict to json
from collections import OrderedDict


ENCRYPT_KEY = b'eg9IaMP_lH6bOcGkvlfwsXlJFVTu-lDvt_tjKcKApIY='

"""
*********************************************************************
                
*********************************************************************
"""


def encrypt_data(txt):
    try:
        # convert integer etc to string first
        txt = str(txt)

        # get the key from settings
        cipher_suite = Fernet(ENCRYPT_KEY)  # key should be byte

        # #input should be byte, so convert the text to byte
        encrypted_text = cipher_suite.encrypt(txt.encode('ascii'))

        # encode to urlsafe base64 format
        encrypted_text = base64.urlsafe_b64encode(
            encrypted_text).decode("ascii")

        return encrypted_text

    except Exception as e:
        # log the error if any
        print(e)
        logging.getLogger("error_logger").error(traceback.format_exc())
        return None


def decrypt_data(txt):
    try:
        # base64 decode
        txt = base64.urlsafe_b64decode(txt)
        cipher_suite = Fernet(ENCRYPT_KEY)
        decoded_text = cipher_suite.decrypt(txt).decode("ascii")
        return decoded_text
    except Exception as e:
        # log the error
        logging.getLogger("error_logger").error(traceback.format_exc())
        return None


"""
string to Json 
"""


def Json_decrypt_data(txt):

    # str Decrypt data
    data = decrypt_data(txt)

    # Convert to json
    json_data = ast.literal_eval(data)
    return json_data


"""
Order Dict to Json
"""


def OrderDict_to_json(data):

    return [json.dumps(i) for i in data]


"""
Date change 
"""


def default(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()


def ChangeDateTimeinJson(data):
    return [json.dumps(i, default=default) for i in data]
