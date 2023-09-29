# -*- coding: utf-8 -*-

import time
import os
import pandas as pd
from print_manager1 import __PrintManager__
from evaluate_data1 import EvaluateData
from connetion_tuple1 import ConnectionTuple


class AnalyzeLog(EvaluateData):
    def __init__(self):
        super(AnalyzeLog, self).__init__()

        # log file path
        self.conn_log = None
        self.dns_log = None
        self.ssl_log = None
        self.x509_log = None

        # log file data
        self.conn_dict = dict()
        self.dns_frame = dict()
        self.ssl_dict = dict()
        self.x509_dict = dict()

        self.open_time = None

    def evaluate_features(self, path_to_dataset):
        self.conn_log = path_to_dataset + '/bro/conn_label.log'
        self.ssl_log = path_to_dataset + '/bro/ssl.log'
        self.x509_log = path_to_dataset + '/bro/x509.log'
        self.dns_log = path_to_dataset + '/bro/dns.log'
        self.load_x509_file()
        self.load_conn_file()
        self.load_dns_file()
        self.load_ssl_file()
        self.create_conn_tuple()

    def read_log(self, filename, date=False, to_dict=True):
        with open(filename) as f:
            for line in f:
                if date == True and '#open' in line:
                    self.open_time = line.strip().split('\t')[1]
                if '#field' in line:
                    fields = line[8:].strip().split('\t')
                    break

        data = pd.read_csv(
            filename,
            sep='\t',
            header=None,
            names=fields,
            skiprows=8,
            skipfooter=1,
            engine='python')

        if 'x509' in filename:
            data = data.drop_duplicates(subset='id').set_index('id')
        else:
            data = data.drop_duplicates(subset='uid').set_index('uid')

        if to_dict:
            data_dict = data.to_dict('index')
            return data_dict
        else:
            return data

    def time_correction(self, current_time):
        current_time = float(current_time)
        time_array = time.strptime(self.open_time, "%Y-%m-%d-%H-%M-%S")
        open_time = time.mktime(time_array)
        if current_time < 1000000000:
            current_time += open_time
        return current_time

    # create conn-conn_tuple from ssl.log
    def create_conn_tuple(self):
        number_of_x509_log = 0
        number_of_ssl_log = 0

        # create connection tuple
        for ssl_uid in self.ssl_dict:
            ssl_log = self.ssl_dict[ssl_uid]
            if ssl_uid in self.conn_dict:
                conn_log = self.conn_dict[ssl_uid]
                label = conn_log['label']
                if 'Background' in label:
                    continue
                elif 'Malicious' not in label and 'Normal' not in label:
                    print("Warning: bad label format", label)
                    continue
                else:
                    pass

                tuple_index = (conn_log['id.orig_h'], conn_log['id.resp_h'],
                               conn_log['id.resp_p'], conn_log['proto'])

                # add ssl log to conn_tuple and conn log to conn_tuple
                if tuple_index in self.conn_tuple:
                    self.conn_tuple[tuple_index].add_ssl_log(ssl_log)
                    self.conn_tuple[tuple_index].add_ssl_flow(conn_log)
                else:
                    self.conn_tuple[tuple_index] = ConnectionTuple(tuple_index)
                    self.conn_tuple[tuple_index].add_ssl_log(ssl_log)
                    self.conn_tuple[tuple_index].add_ssl_flow(conn_log)
                number_of_ssl_log += 1

                # add x509 log to conn_tuple
                cert_chain_fuids = ssl_log['cert_chain_fuids']
                if '-' != cert_chain_fuids:
                    x509_uid = cert_chain_fuids.split(',')[0]
                    if x509_uid in self.x509_dict:
                        x509_log = self.x509_dict[x509_uid]
                        x509_log['ts'] = self.time_correction(x509_log['ts'])
                        self.conn_tuple[tuple_index].add_x509_log(x509_log)
                        self.conn_tuple[tuple_index].is_SNI_in_cert(
                            ssl_log, x509_log)
                        number_of_x509_log += 1

        # add not ssl flow and dns log to conn tuple
        not_ssl_flow, number_of_dns_log, number_of_background_flow = self.add_rest_log(
        )

        self.statistic_of_conn_tuple(number_of_ssl_log, number_of_x509_log,
                                     number_of_dns_log, not_ssl_flow)

    def load_conn_file(self):
        self.conn_dict = self.read_log(self.conn_log)
        print(">>> load %s" % self.conn_log)

    def load_x509_file(self):
        self.x509_dict = self.read_log(self.x509_log, date=True)
        print(">>> load %s" % self.x509_log)

    def load_dns_file(self):
        self.dns_frame = self.read_log(self.dns_log, to_dict=False)
        print(">>> load %s" % self.dns_log)

    def load_ssl_file(self):
        self.ssl_dict = self.read_log(self.ssl_log)
        print(">>> load %s" % self.ssl_log)

    def add_rest_log(self):
        not_ssl_flow = 0
        number_of_dns_log = 0
        number_of_background_flow = 0
        server_set = set()
        for conn_uid in self.conn_dict:
            conn_log = self.conn_dict[conn_uid]
            label = conn_log['label']

            if 'Background' in label:
                number_of_background_flow += 1
                continue
            elif 'Malicious' not in label and 'Normal' not in label:
                print("Warning: bad label format")
                continue
            else:
                pass

            tuple_index = (conn_log['id.orig_h'], conn_log['id.resp_h'],
                           conn_log['id.resp_p'], conn_log['proto'])

            if tuple_index in self.conn_tuple:
                # add dns log to conn_tuple
                server = tuple_index[1]
                if server not in server_set:
                    server_set.add(server)
                    dns_log = self.dns_frame[self.dns_frame['answers'].str.
                                             contains(server)].to_dict('index')
                    for dns_uid in dns_log:
                        self.conn_tuple[tuple_index].add_dns_log(
                            dns_log[dns_uid])
                        number_of_dns_log += 1

                # add not ssl flow to conn_tuple
                service = conn_log['service']
                if service != 'ssl':
                    self.conn_tuple[tuple_index].add_not_ssl_flow(conn_log)
                    not_ssl_flow += 1
                else:
                    pass
        return not_ssl_flow, number_of_dns_log, number_of_background_flow

    def statistic_of_conn_tuple(self, number_of_ssl_log, number_of_x509_log,
                                number_of_dns_log, not_ssl_flow):
        malicious_tuples = 0
        normal_tuples = 0
        malicious_flows = 0
        normal_flows = 0

        for key in self.conn_tuple:
            if self.conn_tuple[key].is_malicious():
                malicious_tuples += 1
                malicious_flows += self.conn_tuple[key].number_of_flows()
            else:
                normal_tuples += 1
                normal_flows += self.conn_tuple[key].number_of_flows()
        print(">>> statistic result of conn_tuple:")
        print("\tssl flow : %d, not ssl flow : %d" % (number_of_ssl_log,
                                                      not_ssl_flow))
        print("\tflow : %d" % (malicious_flows+normal_flows))
        print("\ttuple : %d" % (malicious_tuples+normal_tuples))
        print("\tadd x509 log ", number_of_x509_log)
        print("\tadd dns log ", number_of_dns_log)
