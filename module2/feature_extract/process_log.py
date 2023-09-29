# -*- coding: utf-8 -*-

import time
import os
import pandas as pd
from print_manager import __PrintManager__
from evaluate_data import EvaluateData
from connetion_tuple import ConnectionTuple


class ProcessLogs(EvaluateData):
    def __init__(self):
        super(ProcessLogs, self).__init__()
        self.conn_log = None
        self.dns_log = None
        self.ssl_log = None
        self.x509_log = None

        self.conn_dict = dict()
        self.dns_dict = dict()
        self.ssl_dict = dict()
        self.x509_dict = dict()

        self.ssl_uid_set = set()

        self.number_of_ssl_log = 0
        self.number_of_x509_log = 0

    def evaluate_features(self, path_to_dataset):
        self.conn_log = path_to_dataset + '/bro/conn_label.log'
        self.ssl_log = path_to_dataset + '/bro/ssl.log'
        self.x509_log = path_to_dataset + '/bro/x509.log'
        self.dns_log = path_to_dataset + '/bro/dns.log'
        self.load_x509_file()
        self.load_conn_file()
        self.load_dns_file()
        self.load_ssl_file()
        self.create_conn_tuple(path_to_dataset)

    def read_log(self, filename):
        with open(filename) as f:
            lines = f.read().splitlines()

        data = []
        check_format = False
        for line in lines:
            if '#close' in line:
                check_format = True
            elif line[0] == '#':
                continue
            else:
                data.append(line.split('\t'))

        if not check_format:
            print('%s has bad format !' % filename)
            return False

        for line in lines:
            if '#open' in line:
                date = line.split('\t')[-1]
            elif '#fields' in line:
                fields = line[8:].split('\t')
            else:
                pass

        frame = pd.DataFrame(data, columns=fields)
        return frame, date

    def time_correction(self, flag, open_time, current_time):
        current_time = int(current_time)
        time_array = time.strptime(open_time, "%Y-%m-%d-%H-%M-%S")
        open_time = time.mktime(time_array)
        if flag:
            current_time += open_time
        return current_time

    # create conn-conn_tuple from ssl.log
    def create_conn_tuple(self, path_to_dataset):
        print(">>> creating conn_tuple from " + self.ssl_log)
        background_flows = 0
        number_of_added_x509 = 0
        number_of_added_ssl = 0
        count_lines = 0

        with open(self.ssl_log) as ssl_file:
            for ssl_line in ssl_file:
                if '#' in ssl_line:
                    continue

                count_lines += 1
                ssl_split = ssl_line.split('\t')
                ssl_uid = ssl_split[1]

                # if same ssl, continue (in some ssl.log files are more same ssl lines. It is probably bro error)
                if ssl_uid in self.ssl_uid_set:
                    continue
                else:
                    self.ssl_uid_set.add(ssl_uid)

                # find flow in conn.log by this ssl uid.
                if ssl_uid in self.conn_dict:
                    conn_line = self.conn_dict[ssl_uid]
                else:
                    continue

                conn_split = conn_line.split('\t')
                # 2-srcIpAddress, 3-srcPort, 6-Protocol
                conn_index = (conn_split[2], conn_split[4], conn_split[5],
                              conn_split[6])

                try:
                    label = conn_split[21]
                except:
                    raise IndexError("no label in conn_line.")

                # ignore background flow
                if 'Background' in label:
                    background_flows += 1
                    continue

                if not ('Malicious' in label) and not ('Normal' in label):
                    print("Warning: wrong label ! %s" % label)

                # add ssl log to conn_tuple
                if conn_index in self.conn_tuple:
                    self.conn_tuple[conn_index].add_ssl_log(ssl_line)
                else:
                    self.conn_tuple[conn_index] = ConnectionTuple(conn_index)
                    self.conn_tuple[conn_index].add_ssl_log(ssl_line)

                number_of_added_ssl += 1
                # add x509 log to conn_tuple
                cert_chain_fuids = ssl_split[14]
                if '-' != cert_chain_fuids:
                    x509_uids_list = cert_chain_fuids.split(',')
                    x509_uid = x509_uids_list[0]
                    if x509_uid in self.x509_dict:
                        x509_line = self.x509_dict[x509_uid]
                        self.conn_tuple[conn_index].add_x509_log(x509_line)
                        self.conn_tuple[conn_index].is_SNI_in_cert(
                            ssl_line, x509_line)
                        number_of_added_x509 += 1

        self.add_conn_log()
        self.count_statistic_of_conn(label, count_lines, background_flows,
                                     number_of_added_ssl, number_of_added_x509)

    # load conn_label.log to conn_dict
    def load_conn_file(self):
        self.conn_frame, _ = self.read_log(self.conn_log)
        print(">>> load %s" % self.conn_log)

    # load x509.log to x509_dict.
    def load_x509_file(self):
        flag = None
        self.x509_frame, open_time = self.read_log(self.x509_log)
        for i in range(self.x509_frame.shape[0]):
            t0 = float(self.x509_frame['ts'][i])
            if flag == None:
                if t0 < 1000000000:
                    flag = True
                else:
                    flag = False
            t0 = self.time_correction(flag, open_time, t0)
            self.x509_frame['ts'][i] = t0
        print(">>> load %s" % self.x509_log)

    '''
    Methods for adding not ssl flow from conn.log to connection-conn_tuple
    '''

    def add_conn_log(self):
        not_ssl_flow = 0
        ssl_flow = 0
        with open(self.conn_log) as f:
            for conn_line in f:
                if '#' in conn_line:
                    continue
                conn_split = conn_line.split('\t')
                # 2-srcIpAddress, 3-srcPort, 6-Protocol
                conn_index = (conn_split[2], conn_split[4], conn_split[5],
                              conn_split[6])
                try:
                    label = conn_split[21]
                except:
                    raise IndexError("no label in conn_line")

                conn_uid = conn_split[1]

                if 'Background' in label:
                    continue

                if conn_index in self.conn_tuple:
                    if conn_uid in self.conn_tuple[conn_index].get_ssl_uid():
                        self.conn_tuple[conn_index].add_ssl_flow(
                            conn_line, label)
                        ssl_flow += 1
                    else:
                        self.conn_tuple[conn_index].add_not_ssl_flow(
                            conn_line, label)
                        not_ssl_flow += 1
                else:
                    pass

        print("\t\t<<< ssl flow:", ssl_flow)
        print("\t\t<<< not ssl flow:", not_ssl_flow)

    def count_statistic_of_conn(self, label, number_of_lines, background_flows,
                                number_of_added_ssl, number_of_added_x509):
        # Count number of malicious 4-tuples and normal 4-tuples for printing statistic.
        malicious_tuples = 0
        normal_tuples = 0
        malicious_flows = 0
        normal_flows = 0

        for key in self.conn_tuple:
            if 'Malicious' in label:
                malicious_tuples += 1
                malicious_flows += self.conn_tuple[key].number_of_flows()
            else:
                normal_tuples += 1
                normal_flows += self.conn_tuple[key].number_of_flows()
        __PrintManager__.processLog_evaluate_result(
            malicious_flows, normal_flows, malicious_tuples, normal_tuples,
            number_of_added_ssl, number_of_added_x509)

    def print_feature_manager(self):
        __PrintManager__.print_header_features_printed()
        self.print_ver_cipher_dict()
        self.print_state_dict()
        self.print_cert_key_length_dict()
        self.print_version_of_ssl_dict()

    def print_ver_cipher_dict(self):
        __PrintManager__.print_ver_cipher_dict()
        conn_logs = 0
        ssl_logs = 0
        cipher_suite_dict = dict()
        for key in self.conn_tuple:
            conn_logs += self.conn_tuple[key].number_of_flows()
            ssl_logs += self.conn_tuple[key].get_number_of_ssl_logs()
            for a in self.conn_tuple[key].get_ssl_cipher_dict():
                try:
                    cipher_suite_dict[a] += self.conn_tuple[
                        key].get_ssl_cipher_dict()[a]
                except:
                    cipher_suite_dict[a] = self.conn_tuple[
                        key].get_ssl_cipher_dict()[a]
        print(cipher_suite_dict)
        print("conn_logs", conn_logs)
        print("ssl_logs", ssl_logs)

    def print_state_dict(self):
        __PrintManager__.print_state_dict()
        conn_logs = 0
        ssl_logs = 0
        temp_dict = dict()
        for key in self.conn_tuple:
            conn_logs += self.conn_tuple[key].number_of_flows()
            ssl_logs += self.conn_tuple[key].get_number_of_ssl_logs()
            for a in self.conn_tuple[key].get_conn_state_dict():
                try:
                    temp_dict[a] += self.conn_tuple[key].get_conn_state_dict(
                    )[a]
                except:
                    temp_dict[a] = self.conn_tuple[key].get_conn_state_dict(
                    )[a]
        print(temp_dict)
        print("conn_logs", conn_logs)
        print("ssl_logs", ssl_logs)

    def print_cert_key_length_dict(self):
        __PrintManager__.print_cert_key_length_dict()
        conn_logs = 0
        ssl_logs = 0
        x509_logs = 0
        temp_dict = dict()
        for key in self.conn_tuple.keys():
            conn_logs += self.conn_tuple[key].number_of_flows()
            ssl_logs += self.conn_tuple[key].get_number_of_ssl_logs()
            x509_logs += self.conn_tuple[key].get_size_of_x509_list()
            for a in self.conn_tuple[key].get_cert_key_length_dict().keys():
                try:
                    temp_dict[a] += self.conn_tuple[
                        key].get_cert_key_length_dict()[a]
                except:
                    temp_dict[a] = self.conn_tuple[
                        key].get_cert_key_length_dict()[a]
        print(temp_dict)
        print("conn_logs", conn_logs)
        print("ssl_logs", ssl_logs)
        print("x509_logs", x509_logs)

    def print_version_of_ssl_dict(self):
        __PrintManager__.print_version_of_ssl_dict()
        conn_logs = 0
        ssl_logs = 0
        temp_dict = dict()
        for key in self.conn_tuple:
            conn_logs += self.conn_tuple[key].number_of_flows()
            ssl_logs += self.conn_tuple[key].get_number_of_ssl_logs()
            for a in self.conn_tuple[key].get_ssl_version_dict():
                try:
                    temp_dict[a] += self.conn_tuple[key].get_ssl_version_dict(
                    )[a]
                except:
                    temp_dict[a] = self.conn_tuple[key].get_ssl_version_dict(
                    )[a]
        print(temp_dict)
        print("conn_logs", conn_logs)
        print("ssl_logs", ssl_logs)
