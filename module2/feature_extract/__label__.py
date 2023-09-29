# -*- coding: utf-8 -*-

from . import label_log
from . import config_manager
import os
def label1():
    dataset_path = config_manager.read_config()
    if dataset_path == -1:
        raise ValueError
    malicious_path = dataset_path + "/Malicious"
    print(malicious_path)
    malicious_folder_path = config_manager.get_folders_name(malicious_path)
    for dir_name in malicious_folder_path:
       # print ("xx-Debug:"+dir_name)
         # modify by hegaofeng
         path_to_single = malicious_path + "/" + dir_name
         print(path_to_single)
         if os.path.isdir(path_to_single): # add by hegaofeng
             label_log.label_conn_log(path_to_single)

    # We only aim to detect malicious TLS traffic, thus, we consider all tested traffic are malicious by default.
    '''  
    normal_path = dataset_path + "\\Normal"
 
    normal_folder_path = config_manager.get_folders_name(normal_path)
    # process normal dataset
    for dir_name in normal_folder_path:
       # print ("hgf:"+dir_name)
        #if os.path.isdir(dir_name): # modify by hegaofeng
        path_to_single = normal_path + "\\" + dir_name
        if os.path.isdir(path_to_single): # add by hegaofeng
            label_log.label_conn_log(path_to_single)
    '''
