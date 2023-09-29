# -*- coding: utf-8 -*-
import seaborn as sns
import matplotlib.pyplot as plt
from joblib import load
from time import time
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, auc, roc_curve, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from ..include.Dataset import Dataset
import sys
def rf_predict():
    model = load('RandomForestClassifier.joblib')
    X, y = Dataset().get_testset_randomfrest()

    t0 = time()
    y_pred = model.predict(X)
    print("XX-Debug: y_pred is ",y_pred)
    t1 = time()
    print(">>> predict time: ", t1 - t0)
    return y_pred

