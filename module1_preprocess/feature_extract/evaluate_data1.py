# -*- coding: utf-8 -*-

from print_manager1 import __PrintManager__
import csv


class EvaluateData(object):
    def __init__(self):
        self.conn_tuple = dict()
        self.cert_dict = dict()

    def create_plot_data(self, path, filename):
        __PrintManager__.evaluate_creating_plot()
        self.create_dataset(path, filename)
        __PrintManager__.succ_evaluate_data()

    def create_dataset(self, path, filename):
        index = 0
        ssl_flow = 0
        all_flow = 0
        malicious = 0
        normal = 0

        # file header: label feature
        header = [\
        'srcAddress',\
        'srcPort',\
        'destAddress',\
        'destPort',\
        #'sni',\
        'appProtocol',\
        'tlsSubject',\
        'tlsIssuerDn',\
        'tlsSni',\
        'tlsVersion',\
        'bytesOut',\
        'bytesIn',\
        'pktsIn',\
        'pktsOut',\
        'eventId']
        print("2222222")
        with open(
                path + "/test_1.csv", 'w+',
                newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for key in self.conn_tuple:
                label_feature = [\
                str(self.conn_tuple[key].printoip()),\
                str(self.conn_tuple[key].orgp()),\
                str(self.conn_tuple[key].printdip()),\
                str(self.conn_tuple[key].dstp()),\
                str(self.conn_tuple[key].apppr()),\
                str(self.conn_tuple[key].subject_is_com()),\
                str(self.conn_tuple[key].issuer_is_com()),\
                str(self.conn_tuple[key].printsni()),\
                str(self.conn_tuple[key].ssl_version()),\
                str(self.conn_tuple[key].avg_size()),\
                str(self.conn_tuple[key].recv_sent_size_ratio()),\
                str(self.conn_tuple[key].avg_pkts()),\
                str(self.conn_tuple[key].recv_sent_pkts_ratio()),\
                str(self.conn_tuple[key].eventID())]
                writer.writerow(label_feature)

        print("<<< dataset file dataset-%s.csv successfully created !" %
              filename)
