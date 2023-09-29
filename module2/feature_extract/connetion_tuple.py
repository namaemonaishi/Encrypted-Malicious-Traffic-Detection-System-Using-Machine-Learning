# -*- coding: utf-8 -*-
import numpy as np
import socket
import time
import datetime


class ConnectionTuple:
    def __init__(self, tuple_index):
        # basic 4-tuple (srcIP, dstIP, dstPort, proto)
        self.tuple_index = tuple_index

        # label
        self._is_malicious = None

        # Connection Features
        self.conn_log = []
        self.number_of_ssl_flows = 0
        self.number_of_not_ssl_flows = 0
        self.resp_bytes_list = []
        self.orig_bytes_list = []
        self.conn_state_dict = dict()
        self.duration_list = []
        self.resp_pkts_list = []
        self.orig_pkts_list = []
        self._packet_loss = 0

        # SSL features
        self.ssl_version_dict = dict()
        self.ssl_cipher_dict = dict()
        self.cert_path_length = []
        self.ssl_with_SNI = 0
        self._self_signed_cert = 0
        self._resumed = 0

        # X509 features
        self.number_of_x509 = 0
        self.cert_key_dict = dict()
        self.cert_key_length_list = dict()
        self.cert_serial_set = set()
        self.cert_valid_days = []
        self.invalid_cert_number = 0
        self.san_domain_list = []
        self.cert_validity_percent = []
        self._is_CNs_in_SAN = []
        self._is_SNIs_in_SNA_dns = []
        self._subject_CN_is_IP = []
        self.key_alg = set()
        self.sig_alg = set()
        self.key_type = set()

        self._subject_is_com = []
        self._is_O_in_subject = []
        self._is_CO_in_subject = []
        self._is_ST_in_subject = []
        self._is_L_in_subject = []
        self._subject_only_CN = []

        self._issuer_is_com = []
        self._is_O_in_issuer = []
        self._is_CO_in_issuer = []
        self._is_ST_in_issuer = []
        self._is_L_in_issuer = []
        self._issuer_only_CN = []

        # DNS features
        self.dns_uid_set = set()
        self.TTL_list = []
        self.number_of_IPs_in_DNS = []
        self.domain_name_length = []

    # add conn_log to ssl flow, compute conn features
    def add_ssl_flow(self, conn_log):   #conn_log是一个存储元组的列表
        label = conn_log['label']
        if 'Malicious' in label:
            self._is_malicious = True
        else:
            self._is_malicious = False

        self.conn_log.append(conn_log)
        self.number_of_ssl_flows += 1
        self.compute_conn_features(conn_log)

    # add conn_log to not ssl flow, compute conn features
    def add_not_ssl_flow(self, conn_log):
        label = conn_log['label']
        if 'Malicious' in label:
            self._is_malicious = True
        elif 'Normal' in label:
            self._is_malicious = False
        else:
            print("Warning : wrong label %s" % label)

        self.conn_log.append(conn_log)

        self.number_of_not_ssl_flows += 1
        self.compute_conn_features(conn_log)

    def add_ssl_log(self, ssl_log):
        self.compute_ssl_features(ssl_log)

    def add_x509_log(self, x509_log):
        self.number_of_x509 += 1
        self.compute_x509_features(x509_log)

    def add_dns_log(self, dns_log):
        self.compute_dns_features(dns_log)

    """
    compute features from log files
    """

    # feature extracted from conn_label.log
    def compute_conn_features(self, conn_log):
        # connetion duration
        duration = conn_log['duration']
        try:
            duration = float(duration)
            self.duration_list.append(duration)
        except:
            pass

        # sent bytes
        orig_bytes = conn_log['orig_bytes']
        try:
            orig_bytes_number = int(orig_bytes)
            self.orig_bytes_list.append(orig_bytes_number)
        except:
            pass

        # received bytes
        resp_bytes = conn_log['resp_bytes']
        try:
            resp_bytes_number = int(resp_bytes)
            self.resp_bytes_list.append(resp_bytes_number)
        except:
            pass

        # connection state: S0, S1, SF, REJ, S2, S3, RST0, RSTR, RSTOS0, RSTRH
        conn_state = str(conn_log['conn_state'])
        if conn_state in self.conn_state_dict:
            self.conn_state_dict[conn_state] += 1
        else:
            self.conn_state_dict[conn_state] = 1

        # packet loss
        missed_bytes = conn_log['missed_bytes']
        try:
            missed_bytes_number = int(missed_bytes)
            self._packet_loss += missed_bytes_number
        except:
            pass

        # sent packets
        orig_pkts = conn_log['orig_pkts']
        try:
            orig_pkts_number = int(orig_pkts)
            self.orig_pkts_list.append(orig_pkts_number)
        except:
            pass

        # recieved packets
        resp_pkts = conn_log['resp_pkts']
        try:
            resp_pkts_number = int(resp_pkts)
            self.resp_pkts_list.append(resp_pkts_number)
        except:
            pass

    # feature extracted from ssl.log
    def compute_ssl_features(self, ssl_log):
        # Flag to indicate if the session was resumed reusing the key material exchanged in an earlier connection.
        resumed = ssl_log['resumed']
        if 'T' in resumed:
            self._resumed += 1
        else:
            pass

        # SSL/TLS version that the server chose
        version = ssl_log['version'].upper()
        if version in self.ssl_version_dict:
            self.ssl_version_dict[version] += 1
        elif '-' in version:
            pass
        else:
            self.ssl_version_dict[version] = 1

        # SSL/TLS cipher suite that the server chose
        cipher = ssl_log['cipher']
        if cipher in self.ssl_cipher_dict:
            self.ssl_cipher_dict[cipher] += 1
        elif '-' in version:
            pass
        else:
            self.ssl_cipher_dict[cipher] = 1

        # cert chain
        cert_chain_uid = ssl_log['cert_chain_fuids']
        if cert_chain_uid != '-':
            list_of_x509_uids = cert_chain_uid.split(',')
            self.cert_path_length.append(len(list_of_x509_uids))

        # server name (SNI)
        if '-' not in ssl_log['server_name']:
            self.ssl_with_SNI += 1

    # feature extracted from x509.log
    def compute_x509_features(self, x509_log):
        if '-' not in x509_log['certificate.key_alg']:
            self.key_alg.add(x509_log['certificate.key_alg'])

        if '-' not in x509_log['certificate.sig_alg']:
            self.sig_alg.add(x509_log['certificate.sig_alg'])

        if '-' not in x509_log['certificate.key_type']:
            self.key_type.add(x509_log['certificate.key_type'])

        # check if certificate is valid
        # 6-certificate.not_valid_before, 7-certificate.not_valid_after
        try:
            current_time = float(x509_log['ts'])
            before_time = float(x509_log['certificate.not_valid_before'])
            after_time = float(x509_log['certificate.not_valid_after'])
            if current_time > after_time or current_time < before_time:
                self.invalid_cert_number += 1
            else:
                date1 = time.strftime('%Y-%m-%d-%H-%M-%S',
                                      time.localtime(int(before_time)))
                date2 = time.strftime('%Y-%m-%d-%H-%M-%S',
                                      time.localtime(int(after_time)))
                date1 = time.strptime(date1, "%Y-%m-%d-%H-%M-%S")
                date2 = time.strptime(date2, "%Y-%m-%d-%H-%M-%S")
                d1 = datetime.datetime(date1[0], date1[1], date1[2])
                d2 = datetime.datetime(date2[0], date2[1], date2[2])
                valid_days = (d2 - d1).days
                if valid_days >= 0:
                    self.cert_valid_days.append(valid_days)

                # certificate ratio
                norm_after = after_time - before_time
                current_time_norm = current_time - before_time
                if norm_after > 0:
                    self.cert_validity_percent.append(
                        current_time_norm / norm_after)
        except:
            pass

        # certificate info
        cert_serial = x509_log['certificate.serial']
        if cert_serial not in self.cert_serial_set:
            self.cert_serial_set.add(cert_serial)

            try:
                length = int(cert_key_length)
                self.cert_key_length_list.append(length)
            except:
                pass

            if '-' not in x509_log['san.dns']:
                # number of domain in san in x509
                domains = x509_log['san.dns'].split(',')
                for key in domains:
                    self.san_domain_list.append(key)

                # is CN in san.dns
                subject = x509_log['certificate.subject'].split(',')[0]
                CN = subject[3:]
                if CN in domains:
                    self._is_CNs_in_SAN.append(1)
                else:
                    self._is_CNs_in_SAN.append(0)

                try:
                    socket.inet_aton(CN)
                    self._subject_CN_is_IP.append(1)
                except:
                    self._subject_CN_is_IP.append(0)

        else:
            pass

        # 4-certificate.subject
        subject = x509_log['certificate.subject'].split(',')
        CN = 0
        for key in subject:
            if 'CN=' in key:
                CN += 1
                addr = key[2:]
                if '.com' in key:
                    self._subject_is_com.append(1)
                else:
                    self._subject_is_com.append(0)

            if 'O=' in key:
                self._is_O_in_subject.append(1)
            else:
                self._is_O_in_subject.append(0)

            if 'CO=' in key:
                self._is_CO_in_subject.append(1)
            else:
                self._is_CO_in_subject.append(0)

            if 'ST=' in key:
                self._is_ST_in_subject.append(1)
            else:
                self._is_ST_in_subject.append(0)

            if 'L=' in key:
                self._is_L_in_subject.append(1)
            else:
                self._is_L_in_subject.append(0)

        if CN == len(subject):
            self._subject_only_CN.append(1)
        else:
            self._subject_only_CN.append(0)

        # 5-certificate.issuer
        issuer = x509_log['certificate.issuer'].split(',')
        CN = 0
        for key in issuer:
            if 'CN=' in key:
                CN += 1
                if '.com' in key:
                    self._issuer_is_com.append(1)
                else:
                    self._issuer_is_com.append(0)

            if 'O=' in key:
                self._is_O_in_issuer.append(1)
            else:
                self._is_O_in_issuer.append(0)

            if 'CO=' in key:
                self._is_CO_in_issuer.append(1)
            else:
                self._is_CO_in_issuer.append(0)

            if 'ST=' in key:
                self._is_ST_in_issuer.append(1)
            else:
                self._is_ST_in_issuer.append(0)

            if 'L=' in key:
                self._is_L_in_issuer.append(1)
            else:
                self._is_L_in_issuer.append(0)

        if CN == len(issuer):
            self._issuer_only_CN.append(1)
        else:
            self._issuer_only_CN.append(0)

    # extract feature from dns.log
    def compute_dns_features(self, dns_log):
        domain = dns_log['query']
        self.domain_name_length.append(len(domain))

        dns_ans_list = dns_log['answers'].split(',')
        self.number_of_IPs_in_DNS.append(len(dns_ans_list))

        dstIP = self.tuple_index[1]
        TTLs = dns_log['TTLs'].split(',')
        try:
            pos = dns_ans_list.index(dstIP)
            TTL = float(TTLs[pos])
            self.TTL_list.append(TTL)
        except:
            pass

    """
    advanced computing method
    """

    # get the flow time difference list
    def flow_inter_arrival(self):
        flow_time_list = []
        for conn in self.conn_log:
            flow_time_list.append(float(conn['ts']))
        flow_time_list.sort()

        pre_flow = flow_time_list[:-1]
        next_flow = flow_time_list[1:]
        time_diff_list = [
            next_flow[i] - pre_flow[i] for i in range(len(pre_flow))
        ]

        return time_diff_list

    def std_duration(self):
        if self.duration_list:
            return np.std(self.duration_list)
        else:
            return -1.0

    def avg_sent_size(self):
        if self.orig_bytes_list:
            return np.mean(self.orig_bytes_list)
        else:
            return 0

    def avg_recv_size(self):
        if self.resp_bytes_list:
            return np.mean(self.resp_bytes_list)
        else:
            return 0

    def avg_pkts_sent(self):
        if self.orig_pkts_list:
            return np.mean(self.orig_pkts_list)
        else:
            return 0

    def avg_pkts_recv(self):
        if self.resp_pkts_list:
            return np.mean(self.resp_pkts_list)
        else:
            return 0

    # check if SNI is in cert
    def is_SNI_in_cert(self, ssl_log, x509_log):
        if '-' not in ssl_log['server_name']:
            SNI = ssl_log['server_name']
            # number of domain in san in x509
            if '-' not in x509_log['san.dns']:
                san_dns_list = x509_log['san.dns'].split(',')
                if SNI in san_dns_list:
                    self._is_SNIs_in_SNA_dns.append(1)
                else:
                    self._is_SNIs_in_SNA_dns.append(0)

    """
    Extracted feature
    """

    # 01. maximum duration among all flows
    def max_duration(self):
        if self.duration_list:
            return max(self.duration_list)
        else:
            return 0.0

    # 02. average duration of all flows
    def avg_duration(self):
        if self.duration_list:
            return np.mean(self.duration_list)
        else:
            return 0.0

    # 03. percent of the duration in the range of standard deviation
    def percent_of_std_duration(self):
        std_dur = self.std_duration()
        avg_dur = self.avg_duration()
        upper_dur = avg_dur + abs(std_dur)
        lower_dur = avg_dur - abs(std_dur)
        count = 0
        if std_dur != -1.0:
            for d in self.duration_list:
                if d >= lower_dur and d <= upper_dur:
                    count += 1
            if self.duration_list:
                return float(count / len(self.duration_list))
        return -1.0

    # 04. total_length number of flows
    def number_of_flows(self):
        return self.number_of_ssl_flows + self.number_of_not_ssl_flows

    # 05. ratio of ssl flows
    def ssl_flow_ratio(self):
        flow_number = self.number_of_flows()
        if flow_number > 0:
            return float(self.number_of_ssl_flows / flow_number)
        else:
            return -1.0

    # 06. total_length size of the encrypted conversation
    def avg_size(self):
        return self.avg_sent_size() + self.avg_recv_size()

    # 07. ratio of sent and received bytes
    def recv_sent_size_ratio(self):
        if self.avg_sent_size() > 0:
            return float(self.avg_recv_size() / self.avg_sent_size())
        else:
            return -1.0

    # 08. total_length pkts in the encrypted conversation
    def avg_pkts(self):
        return self.avg_pkts_sent() + self.avg_pkts_recv()

    # 09. ratio of sent and received pkts
    def recv_sent_pkts_ratio(self):
        if self.avg_pkts_sent():
            return float(self.avg_pkts_recv() / self.avg_pkts_sent())
        else:
            return -1.0

    # 10. packet loss
    def packet_loss(self):
        return self._packet_loss

    # 11. percent of established connection
    def percent_of_established_state(self):
        est_state = 0
        total_length_state = 0
        for key in self.conn_state_dict:
            total_length_state += self.conn_state_dict[key]
        if total_length_state > 0:
            # SF-Normal establishment and termination
            est_state += self.conn_state_dict.get('SF', 0)

            # S1-Connection established, not terminated.
            est_state += self.conn_state_dict.get('S1', 0)

            # S2-Connection established and close attempt by originator seen (but no reply from responder.
            est_state += self.conn_state_dict.get('S2', 0)

            # S3-Connection established and close attempt by responder seen (but no reply from originator.
            est_state += self.conn_state_dict.get('S3', 0)

            # RST0-Connection established, originator aborted (sent a RST.
            est_state += self.conn_state_dict.get('RSTO', 0)

            # RSTR-Responder sent a RST.
            est_state += self.conn_state_dict.get('RSTR', 0)
            return float(est_state / total_length_state)
        return -1.0

    # 12. average time difference between flows sent
    def avg_time_diff(self):
        time_diff = self.flow_inter_arrival()
        if time_diff:
            return np.mean(time_diff)
        else:
            return 0.0

    # 13. standard deviation time difference between flows sent
    def std_time_diff(self):
        time_diff = self.flow_inter_arrival()
        if time_diff:
            return np.std(time_diff)
        else:
            return -1.0

    # 14. maximum time difference between flows sent
    def max_time_diff(self):
        time_diff = self.flow_inter_arrival()
        if time_diff:
            return max(time_diff)
        else:
            return 0.0

    # 15. ratio TLS and SSL
    def ssl_tls_ratio(self):
        tls = 0
        ssl = 0
        if self.ssl_version_dict:
            for key in self.ssl_version_dict:
                if 'TLS' in key:
                    tls += 1
                if 'SSL' in key:
                    ssl += 1
            if tls > 0:
                return float(ssl / tls)
        return -1.0

    # 16. average number of ssl/tls version
    def ssl_version(self):
        if self.ssl_version_dict:
            ssl_version = list(self.ssl_version_dict.keys())
            ssl_version.sort()
            return ssl_version
        else:
            return None

    # 17. cipher-suite list selected by server
    def cipher_suite_server(self):
        if self.ssl_cipher_dict:
            cipher_suite = list(self.ssl_cipher_dict.keys())
            cipher_suite.sort()
            return cipher_suite
        else:
            return None

    # 19. 1 if this is a resumed connetion, 0 otherwise
    def resumed(self):
        return self._resumed

    # 20. ratio of self_signed cert
    def self_signed_ratio(self):
        if self.number_of_ssl_flows:
            return float(self._self_signed_cert / self.number_of_ssl_flows)
        return -1.0

    # 21. average public key length
    def avg_key_length(self):
        if self.cert_key_length_list:
            return np.mean(self.cert_key_length_list)
        else:
            return -1.0

    # 22. average cert validation in days
    def avg_cert_valid_day(self):
        if self.cert_valid_days:
            return np.mean(self.cert_valid_days)
        else:
            return 0.0

    # 23. standard deviation cert validation in days
    def std_cert_valid_day(self):
        if self.cert_valid_days:
            return np.std(self.cert_valid_days)
        else:
            return -1.0

    # 24. percent of valid certificate
    def percent_of_valid_cert(self):
        valid_cert = len(self.cert_validity_percent)
        total = valid_cert + self.invalid_cert_number
        if total > 0:
            return float(valid_cert / total)
        else:
            return -1.0

    # 25. average of cert validity percent
    def avg_valid_cert_percent(self):
        if self.cert_validity_percent:
            return np.mean(self.cert_validity_percent)
        else:
            return 0.0

    # 26. total number of different cert serial
    def number_of_cert_serial(self):
        return len(self.cert_serial_set)

    # 27. Number of different domains in certificate
    def number_of_domains_in_cert(self):
        domain_set = set(self.san_domain_list)
        return len(domain_set)

    # 28. average signed certificate in the first certificate
    def avg_cert_path(self):
        if self.cert_path_length:
            return np.mean(self.cert_path_length)
        else:
            return -1.0

    # 29. how many ssl log has x509 information
    def x509_ssl_ratio(self):
        if self.number_of_ssl_flows:
            return float(self.number_of_x509 / self.number_of_ssl_flows)
        else:
            return -1.0

    # 30. how many ssl flows have SNI (server name)
    def SNI_ssl_ratio(self):
        if self.number_of_ssl_flows:
            return float(self.ssl_with_SNI / self.number_of_ssl_flows)
        else:
            return -1.0

    # 31. whether all SNIs are in san.dns
    def is_SNIs_in_SNA_dns(self):
        if self._is_SNIs_in_SNA_dns:
            if 0 in self._is_SNIs_in_SNA_dns:
                return 0
            return 1
        return -1

    # 32. whether all CNs are in san.dns
    def is_CNs_in_SNA_dns(self):
        if self._is_CNs_in_SAN:
            if 0 in self._is_CNs_in_SAN:
                return 0
            return 1
        return -1

    def subject_CN_is_IP(self):
        if self._subject_CN_is_IP:
            return np.mean(self._subject_CN_is_IP)
        else:
            return 0

    # 33. cert key algorithm
    def cert_key_alg(self):
        if self.key_alg:
            key_alg = list(self.key_alg)
            key_alg.sort()
            return key_alg
        else:
            return None

    # 34. cert signature algorithm
    def cert_sig_alg(self):
        if self.sig_alg:
            sig_alg = list(self.sig_alg)
            sig_alg.sort()
            return sig_alg
        else:
            return None

    def cert_key_type(self):
        if self.key_type:
            key_type = list(self.key_type)
            key_type.sort()
            return key_type
        else:
            return None

    def subject_is_com(self):
        if self._subject_is_com:
            return np.mean(self._subject_is_com)
        else:
            return 0

    def is_O_in_subject(self):
        if self._is_O_in_subject:
            return np.mean(self._is_O_in_subject)
        else:
            return 0

    def is_CO_in_subject(self):
        if self._is_CO_in_subject:
            return np.mean(self._is_CO_in_subject)
        else:
            return 0

    def is_ST_in_subject(self):
        if self._is_ST_in_subject:
            return np.mean(self._is_ST_in_subject)
        else:
            return 0

    def is_L_in_subject(self):
        if self._is_L_in_subject:
            return np.mean(self._is_L_in_subject)
        else:
            return 0

    def subject_only_CN(self):
        if self._subject_only_CN:
            return np.mean(self._subject_only_CN)
        else:
            return 0

    def issuer_is_com(self):
        if self._issuer_is_com:
            return np.mean(self._issuer_is_com)
        else:
            return 0

    def is_O_in_issuer(self):
        if self._is_O_in_issuer:
            return np.mean(self._is_O_in_issuer)
        else:
            return 0

    def is_CO_in_issuer(self):
        if self._is_CO_in_issuer:
            return np.mean(self._is_CO_in_issuer)
        else:
            return 0

    def is_ST_in_issuer(self):
        if self._is_ST_in_issuer:
            return np.mean(self._is_ST_in_issuer)
        else:
            return 0

    def is_L_in_issuer(self):
        if self._is_L_in_issuer:
            return np.mean(self._is_L_in_issuer)
        else:
            return 0

    def issuer_only_CN(self):
        if self._issuer_only_CN:
            return np.mean(self._issuer_only_CN)
        else:
            return 0

    # 35. TTL
    def avg_TTL(self):
        if self.TTL_list:
            return np.mean(self.TTL_list)
        else:
            return 0.0

    # 36. domain name
    def avg_domain_name_length(self):
        if self.domain_name_length:
            return np.mean(self.domain_name_length)
        else:
            return 0.0

    # 37.
    def std_domain_name_length(self):
        if self.domain_name_length:
            return np.std(self.domain_name_length)
        else:
            return -1.0

    # 38.
    def avg_IPs_in_DNS(self):
        if self.number_of_IPs_in_DNS:
            return np.mean(self.number_of_IPs_in_DNS)
        else:
            return 0.0

    # label
    def is_malicious(self):
        if self._is_malicious:
            return 1
        else:
            return 0

    def get_number_of_ssl_flows(self):
        return self.number_of_ssl_flows