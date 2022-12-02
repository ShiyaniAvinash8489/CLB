"""
********************
    Packages
********************
"""

# Logging - Logger
import logging

# Os
import os

# settings
from django.conf import settings


"""
********************
    Logic 
********************
"""
Dir_folder = settings.BASE_DIR


def Error_Log(msg):

    logging.basicConfig(filename=os.path.join(Dir_folder, "Logs\Error_Log.log"),
                        format='%(asctime)s %(levelname)s %(message)s',
                        filemode='a')

    logger = logging.getLogger()
    logger.error(msg)
