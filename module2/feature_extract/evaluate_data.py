# -*- coding: utf-8 -*-

from print_manager import __PrintManager__
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
        'label',\
        'ssl_version',\
        'cipher_suite_server',\
        'cert_key_alg',\
        'cert_sig_alg',\
        'cert_key_type',\
        'max_duration',\
        'avg_duration',\
        'percent_of_std_duration',\
        'number_of_flows',\
        'ssl_flow_ratio',\
        'avg_size',\
        'recv_sent_size_ratio',\
        'avg_pkts',\
        'recv_sent_pkts_ratio',\
        'packet_loss',\
        'percent_of_established_state',\
        'avg_time_diff',\
        'std_time_diff',\
        'max_time_diff',\
        'ssl_tls_ratio',\
        'resumed',\
        'self_signed_ratio',\
        'avg_key_length',\
        'avg_cert_valid_day',\
        'std_cert_valid_day',\
        'percent_of_valid_cert',\
        'avg_valid_cert_percent',\
        'number_of_cert_serial',\
        'number_of_domains_in_cert',\
        'avg_cert_path',\
        'x509_ssl_ratio',\
        'SNI_ssl_ratio',\
        'is_SNIs_in_SNA_dns',\
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
        'issuer_only_CN',\
        'avg_TTL',\
        'avg_domain_name_length',\
        'std_domain_name_length',\
        'avg_IPs_in_DNS']
        print("111111111")
        with open(
                path + "/test.csv", 'w+',
                newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for key in self.conn_tuple:
                label_feature = [\
                str(self.conn_tuple[key].is_malicious()),\
                str(self.conn_tuple[key].ssl_version()),\
                str(self.conn_tuple[key].cipher_suite_server()),\
                str(self.conn_tuple[key].cert_key_alg()),\
                str(self.conn_tuple[key].cert_sig_alg()),\
                str(self.conn_tuple[key].cert_key_type()),\
                str(self.conn_tuple[key].max_duration()),\
                str(self.conn_tuple[key].avg_duration()),\
                str(self.conn_tuple[key].percent_of_std_duration()),\
                str(self.conn_tuple[key].number_of_flows()),\
                str(self.conn_tuple[key].ssl_flow_ratio()),\
                str(self.conn_tuple[key].avg_size()),\
                str(self.conn_tuple[key].recv_sent_size_ratio()),\
                str(self.conn_tuple[key].avg_pkts()),\
                str(self.conn_tuple[key].recv_sent_pkts_ratio()),\
                str(self.conn_tuple[key].packet_loss()),\
                str(self.conn_tuple[key].percent_of_established_state()),\
                str(self.conn_tuple[key].avg_time_diff()),\
                str(self.conn_tuple[key].std_time_diff()),\
                str(self.conn_tuple[key].max_time_diff()),\
                str(self.conn_tuple[key].ssl_tls_ratio()),\
                str(self.conn_tuple[key].resumed()),\
                str(self.conn_tuple[key].self_signed_ratio()),\
                str(self.conn_tuple[key].avg_key_length()),\
                str(self.conn_tuple[key].avg_cert_valid_day()),\
                str(self.conn_tuple[key].std_cert_valid_day()),\
                str(self.conn_tuple[key].percent_of_valid_cert()),\
                str(self.conn_tuple[key].avg_valid_cert_percent()),\
                str(self.conn_tuple[key].number_of_cert_serial()),\
                str(self.conn_tuple[key].number_of_domains_in_cert()),\
                str(self.conn_tuple[key].avg_cert_path()),\
                str(self.conn_tuple[key].x509_ssl_ratio()),\
                str(self.conn_tuple[key].SNI_ssl_ratio()),\
                str(self.conn_tuple[key].is_SNIs_in_SNA_dns()),\
                str(self.conn_tuple[key].is_CNs_in_SNA_dns()),\
                str(self.conn_tuple[key].subject_CN_is_IP()),\
                str(self.conn_tuple[key].subject_is_com()),\
                str(self.conn_tuple[key].is_O_in_subject()),\
                str(self.conn_tuple[key].is_CO_in_subject()),\
                str(self.conn_tuple[key].is_ST_in_subject()),\
                str(self.conn_tuple[key].is_L_in_subject()),\
                str(self.conn_tuple[key].subject_only_CN()),\
                str(self.conn_tuple[key].issuer_is_com()),\
                str(self.conn_tuple[key].is_O_in_issuer()),\
                str(self.conn_tuple[key].is_CO_in_issuer()),\
                str(self.conn_tuple[key].is_ST_in_issuer()),\
                str(self.conn_tuple[key].is_L_in_issuer()),\
                str(self.conn_tuple[key].issuer_only_CN()),\
                str(self.conn_tuple[key].avg_TTL()),\
                str(self.conn_tuple[key].avg_domain_name_length()),\
                str(self.conn_tuple[key].std_domain_name_length()),\
                str(self.conn_tuple[key].avg_IPs_in_DNS())]
                writer.writerow(label_feature)

        print("<<< dataset file dataset-%s.csv successfully created !" %
              filename)
