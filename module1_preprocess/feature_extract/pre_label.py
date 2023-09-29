# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
import label_log1
import config_manager1
def m1_label():
    dataset_path = config_manager1.read_config()
    if dataset_path == -1:
        raise ValueError
    malicious_path = dataset_path + "/Malicious"
    malicious_folder_path = config_manager1.get_folders_name(malicious_path)
    for dir_name in malicious_folder_path:
       # print ("xx-Debug:"+dir_name)
         # modify by hegaofeng
         path_to_single = malicious_path + "/" + dir_name
         if os.path.isdir(path_to_single): # add by hegaofeng
             label_log1.label_conn_log(path_to_single)

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
