# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
from joblib import load
from time import time
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, auc, roc_curve, confusion_matrix
from lightgbm import LGBMClassifier
#from dataset_split import DataSplit

def LGBM():
    model = load('LGBMClassifier.joblib')
    import sys
    sys.path.append(".")
    from ..include.Dataset import Dataset
    X, y = Dataset().get_testset_lightGBM()
    t0 = time()
    y_pred = model.predict(X, num_iteration=model.best_iteration_)
    print("XX-Debug: y_pred=",y_pred)
    t1 = time()

    import sys
    import seaborn as sns
    sys.path.append(".")
    from ..include.AlarmMetric import false_positive_rate, false_negative_rate, false_discovery_rate
    print(">>> predict time: ", t1 - t0)
    return y_pred

