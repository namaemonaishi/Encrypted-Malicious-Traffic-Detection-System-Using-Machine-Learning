# -*- coding: utf-8 -*-

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import tensorflow as tf
import configparser


def get_config_file():
    cfg_file = tf.io.gfile.glob('*.cfg') # add io and change Glob to glob by hegaofeng
    if cfg_file:
        return cfg_file[0]
    else:
        raise FileNotFoundError("config file not found")


def read_config():
    name_of_config = get_config_file()
    config = configparser.ConfigParser(allow_no_value=True)
    if config:
        config.read(name_of_config)
    else:
        raise IOError("cannot read config file")

    try:
        dataset_path = config.get('PATH', 'path_to_dataset')
        return dataset_path
    except:
        raise ValueError("config path has bad format")


def get_folders_name(file_path):
    return os.listdir(file_path)