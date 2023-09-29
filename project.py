import sys
import warnings
from module2.machine_learning.detection import detect_randomforest
from module2.machine_learning.detection import detect_lightGBM
from module2.feature_extract import __label__
from module2.feature_extract import module2main
import os
os.system("zeek -r *.pcap")
ipstr = input("please input the IP that to be detected:")
#31.13.69.203
with open("IPadr.txt", "w") as f:
	f.write("Malicious\n" + ipstr)
os.system("mv *.log IPadr.txt /home/lsl/Desktop/project/module2/dataset/Malicious/test/bro")
__label__.label1()
module2main.start1()
randomresult=detect_randomforest.rf_predict()
lgbmresult=detect_lightGBM.LGBM()
from preprocess import preprocessing,a
from module1_preprocess.feature_extract import pre_label
from module1_preprocess.feature_extract import pre_main
pre_label.m1_label()
pre_main.m1_main()
from module1 import main_train 
train_path = '/home/lsl/Desktop/project/module1/train.csv'
warnings.filterwarnings('ignore')
md1result=main_train.train_func(train_path)
a=md1result
print("<------------------------------------------------------------------------------>")
print("<------------------------------predict result---------------------------------->")
print("<------------------------------------------------------------------------------>")
preprocessing()
if md1result:
    print("the ml-certificate module's predict result is MALICIOUS!")
else:
    print("the ml-certificate module's predict result is NORMAL!")
if randomresult:
    print("the random-forest module's predict result is MALICIOUS!")
else:
    print("the random-forest module's predict result is NORMAL!")
if lgbmresult:
    print("the gbdt module's predict result is MALICIOUS!")
else:
    print("the gbdt module's predict result is NORMAL!")
print("<------------------------------------------------------------------------------>")
print("<----------------------------relevant features--------------------------------->")
print("<------------------------------------------------------------------------------>")
import csv
# 指定csv文件路径
csv_file_path = "/home/lsl/Desktop/project/module2/dataset/data_model/test_1.csv"

# 指定要打印的label
labels_to_print = ["tlsSubject", "tlsIssuerDn", "tlsSni"]

# 打开csv文件
with open(csv_file_path, newline='') as csvfile:
    # 读取csv文件内容
	reader = csv.reader(csvfile)
    # 获取label行
	label_row = next(reader)
    # 获取数值行
	value_row = next(reader)
    # 遍历label行和数值行，找到需要打印的label，并以"label：数值"的形式依次打印出来
	for label, value in zip(label_row, value_row):
		if label in labels_to_print:
			print("{}: {}".format(label, value))
# 指定csv文件路径
csv_file_path1 = "/home/lsl/Desktop/project/module2/dataset/data_model/test.csv"

# 指定需要特殊处理的label
labels_to_process1 = ["percent_of_std_duration", "ssl_flow_ratio", "lrecv_sent_pkts_ratio","percent_of_established_state","percent_of_valid_cert","avg_valid_cert_percent","x509_ssl_ratio",'is_SNIs_in_SNA_dns',\
        'is_CNs_in_SNA_dns',\
        'subject_CN_is_IP',\
        'subject_is_com',\
        'is_O_in_subject',\
        'is_CO_in_subject',\
        'is_ST_in_subject',\
        'is_L_in_subject',\
        'subject_only_CN',\
        'issuer_is_com',\
        'is_O_in_issuer',\
        'is_CO_in_issuer',\
        'is_ST_in_issuer',\
        'is_L_in_issuer',\
        'issuer_only_CN']

# 打开csv文件
with open(csv_file_path1, newline='') as csvfile1:
    # 读取csv文件内容
	reader = csv.reader(csvfile1)
    # 获取label行
	label_row = next(reader)
    # 获取数值行
	value_row = next(reader)
    # 遍历label行和数值行，对需要特殊处理的label进行处理，并以"label：数值"的形式依次打印出来
	for label, value in zip(label_row, value_row):
		if label in labels_to_process1:
				value1=float(value)*100
				print("{}: {}%".format(label, value1))
		else:
			print("{}: {}".format(label, value))
