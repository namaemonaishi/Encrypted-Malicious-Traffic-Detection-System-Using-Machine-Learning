# -*- coding: UTF-8 -*-
import sys
import time
import os
sys.path.append(os.path.dirname(__file__))
import config_manager as ConfigManager
#from . import print_manager
from print_manager import __PrintManager__
from analyze_log import AnalyzeLog
def start1():
    t0 = time.time()
    __PrintManager__.welcome_header()

    # The argument of this program should be name of the resulting plot data file.
    # If there is no argument, default name for plot data is: 'dataset-YYYYMMDD-HHMMSS.csv'
    local_time = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    result_file = local_time
    if len(sys.argv) == 2:
        result_file = sys.argv[1]

    # Get path to multi dataset from config file.
    # [0] - path to dataset
    dataset_path = ConfigManager.read_config()
    malicious_path = dataset_path + "/Malicious"
    #normal_path = dataset_path + "/Normal"
    #plot_data_path = "../data_model"
    plot_data_path = dataset_path+"/data_model" # add by hegaofeng
    if dataset_path == -1:
        raise ValueError

    # Get name list of malicious and normal data folders
    malicious_folder_path = ConfigManager.get_folders_name(malicious_path)
    #normal_folder_path = ConfigManager.get_folders_name(normal_path)
    folder_path = malicious_folder_path
    #folder_path = malicious_folder_path + normal_folder_path
    __PrintManager__.dataset_folder_header(folder_path, len(folder_path))

    # 2. Create 4-tuples, evaluate features
    log = AnalyzeLog()

    '''
    # process normal dataset
    for dir_name in normal_folder_path:
        path_to_single = normal_path + "/" + dir_name
        __PrintManager__.single_folder_header(path_to_single)
        log.evaluate_features(path_to_single)
        __PrintManager__.succ_single_folder_header()
        log.create_plot_data(plot_data_path, dir_name)
    '''

    # process malicious dataset
    for dir_name in malicious_folder_path:
        path_to_single = malicious_path + "/" + dir_name
        print(path_to_single)
        __PrintManager__.single_folder_header(path_to_single)
        log.evaluate_features(path_to_single)
        __PrintManager__.succ_single_folder_header()
        log.create_plot_data(plot_data_path, dir_name)

    t1 = time.time()
    print("\n<<< Total approximate running time: %f min." % ((t1 - t0) / 60.0))
