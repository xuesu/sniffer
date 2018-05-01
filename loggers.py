# -*- coding:utf-8 -*-
"""
@author: xuesu
"""

import os
import logging
import logging.config
import logging.handlers


def new_logger(name, level):
    logger = logging.getLogger(name)
    stream_handler = logging.StreamHandler()
    file_handler = logging.handlers.TimedRotatingFileHandler(
        os.path.join('logs', "{}.log".format(name)), when='D')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%m-%d %H:%M:%S')
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    file_handler.setLevel('INFO')
    logger.setLevel(level)
    return logger

