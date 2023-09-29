# -*- coding: utf-8 -*-

import pandas as pd
import time
import socket


def time_correction(flag, open_time, current_time):
    current_time = int(current_time)
    time_array = time.strptime(open_time, "%Y-%m-%d-%H-%M-%S")
    open_time = time.mktime(time_array)
    if flag:
        current_time += open_time
    return current_time


filename = '/home/lsl/Desktop/malicious-TLS-detection-by-ML-master/Dataset/Malicious/CTU-Malware-Capture-Botnet-301-1/bro/dns.log'
with open(filename) as f:
    for line in f:
        if '#field' in line:
            fields = line[8:].strip().split('\t')
            break

data = pd.read_csv(
    filename,
    sep='\t',
    header=None,
    names=fields,
    index_col=1,
    skiprows=8,
    skipfooter=1,
    engine='python').drop_duplicates()

print(data[data['answers'].str.contains('173.255.212.208')])
