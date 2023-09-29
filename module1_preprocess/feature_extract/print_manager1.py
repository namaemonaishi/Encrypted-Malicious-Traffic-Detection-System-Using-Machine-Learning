# -*- coding: UTF-8 -*-

from time import time


class PrintManager:
    def __init__(self):
        self.index_of_folder = 1
        self.t0 = None
        self.t1 = None
        self.dash_line = "<---------------------------------------------------------------------------->"

    def set_finish_time(self):
        self.t1 = time()

    def welcome_header(self):
        print(self.dash_line)
        print("<<< Welcome to Feature-Extract project")

    def dataset_folder_header(self, path, size):
        print(self.dash_line)
        print("<<< Program will start to evaluate dataset folder:")
        print(path)
        print("<<< total number of folders: %d" % size)
        print(self.dash_line)

    def single_folder_header(self, path_to_single):
        self.t0 = time()
        self.index_of_folder += 1

    def succ_single_folder_header(self):
        self.t1 = time()
        print("<<< approximate running time: %.2f sec." % (self.t1 - self.t0))
        print(self.dash_line)

    def evaluate_creating_plot(self):
        print("<<< main.py: Creating dataset ...")

    def succ_evaluate_data(self):
        print("\t<<< main.py: Process complete !!!")

    # -------------- ProcessLog -------------------------------------------
    def processLog_evaluating(self):
        print(self.dash_line)
        print("<<< ProcessLog.py: start to evaluate logs.")

    # Malicious_flows, normal_flows, Malicious_tuples, normal_tuples, number_adding_ssl, number_of_adding_x509
    def processLog_evaluate_result(self, Malicious_flows, normal_flows,
                                   Malicious_tuples, normal_tuples,
                                   number_adding_ssl, number_of_adding_x509):
        print("\t\t<<< ProcessLog.py: Malicious 4-tuples:", Malicious_tuples)
        print("\t\t<<< ProcessLog.py: Normal 4-tuples:", normal_tuples)
        print("\t\t<<< ProcessLog.py: Malicious flows[conn]:", Malicious_flows)
        print("\t\t<<< ProcessLog.py: Normal flows[conn]:", normal_flows)
        print("\t\t<<< ProcessLog.py: Number of added ssl logs:",
              number_adding_ssl)
        print("\t\t<<< ProcessLog.py: Number of added x509 logs:",
              number_of_adding_x509)

    def processLog_evaluate_ssl(self):
        print("\t<<< ProcessLogs.py: Evaluating of ssl file...")

    def processLog_no_ssl_logs(self):
        print("\t\t<<< ProcessLogs.py: This data set does not have ssl logs.")

    def processLog_number_of_addes_ssl(self, count_lines):
        print("\t\t<<< ProcessLogs.py: Pocet radku v ssl.log: ", count_lines)

    def processLog_number_of_addes_x509(self, count_lines):
        print("\t\t<<< ProcessLogs.py: Pocet radku v x509.log: ", count_lines)

    def processLog_check_tuples(self):
        print("\t<<< ProcessLogs.py: Checking connections...")

    def processLog_correct(self):
        print("\t\t<<< ProcessLog.py: Connections are correct.")

    def processLog_result_number_of_flows(self, normal, malicious):
        print(
            "\t\t<<< ProcessLog.py: Total numbers of used flows is: malicious:",
            malicious, "normal:", normal)

    def processLog_warning(self):
        print("\t\t<<< ProcessLog.py: Connetions have dual flow !")

    def print_header_certificates(self):
        print(self.dash_line)
        print("<<< Printing certificates:")

    def print_header_features_printed(self):
        print(self.dash_line)
        print("<<< Printing features:")

    def print_ver_cipher_dict(self):
        print(self.dash_line)
        print("<<< cipher suite (server chooses) ")

    def print_state_dict(self):
        print(self.dash_line)
        print(">>> connection state")

    def print_cert_key_length_dict(self):
        print(self.dash_line)
        print(">>> certificate key length")

    def print_version_of_ssl_dict(self):
        print(self.dash_line)
        print(">>> TLS/SSL version")

    def print_certificate_serial(self):
        print(self.dash_line)
        print(">>> certificate serial")

    def create_dataset_info(self):
        print(self.dash_line)
        print(">>> dataset information")


__PrintManager__ = PrintManager()
