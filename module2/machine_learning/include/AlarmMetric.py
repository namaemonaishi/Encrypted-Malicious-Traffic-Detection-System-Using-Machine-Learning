# -*- coding: utf-8 -*-

from sklearn.metrics import confusion_matrix


def false_positive_rate(y_true, y_predict):
    TN, FP, FN, TP = confusion_matrix(y_true, y_predict).ravel()
    FPR = FP / (FP + TN)
    return FPR


def false_negative_rate(y_true, y_predict):
    TN, FP, FN, TP = confusion_matrix(y_true, y_predict).ravel()
    FNR = FN / (FN + TP)
    return FNR


def false_discovery_rate(y_true, y_predict):
    TN, FP, FN, TP = confusion_matrix(y_true, y_predict).ravel()
    FDR = FP / (FP + TP)
    return FDR