import csv
a=2
# 读取test_1.csv数据集的tlsSubject、tlsIssuerDn和tlsSni字段的值
def preprocessing():
    with open('/home/lsl/Desktop/project/module2/dataset/data_model/test_1.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            tlsSubject = row['tlsSubject']
            tlsIssuerDn = row['tlsIssuerDn']
            tlsSni = row['tlsSni']

            # 在data.csv中查找相应的字段值
            with open('data.csv', 'r') as datafile:
                datareader = csv.DictReader(datafile)
                found = False
                for datarow in datareader:
                    if datarow['tlsSubject'] == tlsSubject and datarow['tlsIssuerDn'] == tlsIssuerDn and datarow['tlsSni'] == tlsSni:
                        found = True
                        break
                # 输出结果
                if found:
                    print("the 1st module's predict result is malicious certificate FOUND!")
                    # 如果结果为1，那么将tlsSubject、tlsIssuerDn和tlsSni三个字段的内容存储在data.csv中
                else:
                    print("the certificate has not been saved")
                if a and found == False:
                    writer = csv.writer(datafile)
                    writer.writerow([tlsSubject, tlsIssuerDn, tlsSni])
