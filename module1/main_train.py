# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
import sys
import os
from sklearn.metrics import classification_report
from scipy import stats,sparse
import time
import re
import lightgbm as lgb
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold,KFold,train_test_split
from sklearn.metrics import f1_score,accuracy_score,roc_auc_score
from sklearn.metrics import roc_auc_score,recall_score,accuracy_score,log_loss,precision_score
import matplotlib.pyplot as plt
import gensim
import pickle
from gensim.models import FastText, Word2Vec
import warnings
warnings.filterwarnings('ignore')

def load_feature(inputfile = 'cnt_code_dict.pkl'):
    with open(inputfile, 'rb') as f:
        feature = pickle.load(f)
    return feature

def save_feature(feature, outputfile = 'cnt_code_dict.pkl'):
    with open(outputfile, 'wb') as f:
        pickle.dump(feature, f)
    return

def kfold_stats_feature(train, test, feats, k):
    folds = StratifiedKFold(n_splits=k, shuffle=True, random_state=2020)  
    train['fold'] = None
    for fold_, (trn_idx, val_idx) in enumerate(folds.split(train, train['label'])):
        train.loc[val_idx, 'fold'] = fold_  #标记所在的行在第几个折叠中

    kfold_features = []
    for feat in feats:
        nums_columns = ['label']
        for f in nums_columns:
            colname = feat + '_' + f + '_kfold_mean'
            kfold_features.append(colname)
            train[colname] = None
            for fold_, (trn_idx, val_idx) in enumerate(folds.split(train, train['label'])):
                tmp_trn = train.iloc[trn_idx]
                order_label = tmp_trn.groupby([feat])[f].mean()
                tmp = train.loc[train.fold == fold_, [feat]]
                train.loc[train.fold == fold_, colname] = tmp[feat].map(order_label)
                # fillna
                global_mean = train[f].mean()
                train.loc[train.fold == fold_, colname] = train.loc[train.fold == fold_, colname].fillna(global_mean)
            train[colname] = train[colname].astype(float)

        for f in nums_columns:
            colname = feat + '_' + f + '_kfold_mean'
            test[colname] = None
            order_label = train.groupby([feat])[f].mean()
            test[colname] = test[feat].map(order_label)
            # fillna
            global_mean = train[f].mean()
            test[colname] = test[colname].fillna(global_mean)
            test[colname] = test[colname].astype(float)
    del train['fold']
    return train, test

class MySentences(object):
    def __init__(self, sentences):
        self.sentences = sentences

    def __iter__(self):
        # print('.....')3
        for line in self.sentences:
            yield line.split()

def get_w2v(df, col, embed_size,name):
    dd = df[['eventId',col]].copy()
    sen = dd[col].values.tolist()
    try:
        print('test')
        model = gensim.models.KeyedVectors.load_word2vec_format('fusai_w2v_{}_{}.model.bin'.format(col, embed_size), binary=True)
    except:
        all_sentences = MySentences(sen)
        model = Word2Vec(all_sentences, vector_size=embed_size, window=3, min_count=2,epochs=10, workers=8, sg=1, seed=42)
        model.wv.save_word2vec_format('fusai_w2v_{}_{}.model.bin'.format(col, embed_size),binary=True)

    w2v = []
    for s in sen:
        vec = []
        for word in s.split(' '):
            if word not in model.wv.vocab:
                continue
            vec.append(model[word])
        if len(vec) > 0:
            w2v.append(np.mean(vec, axis=0))
        else:
            w2v.append(np.zeros(embed_size))
#     del sen;gc.collect()
    w2v_time_df = pd.DataFrame(w2v)
#     del w2v;gc.collect()
    w2v_time_df.columns = ['{}_{}_w2v_{}'.format(name, col,i+1) for i in w2v_time_df.columns]
    w2v_time_df['eventId'] = dd['eventId'].values
#     del model;gc.collect()
    return w2v_time_df
    
def train_func(train_path):
    test = pd.read_csv('/home/lsl/Desktop/project/module2/dataset/data_model/test_1.csv')
    def f1_score(y,pred):
        P = precision_score(y,pred)
        R = recall_score(y,pred)
        return 4*P*R/(P+3*R)
    
    def find_threshold(oof_pred,y,left=0,right=1,display=True,verbose=True):
        oof_temp = oof_pred.copy()
        plt_ = pd.DataFrame()
        best_threshold=0
        best_f1 = 0
        best_num = 0
        for n,i in enumerate(np.linspace(left,right,66)):
            oof_temp[oof_pred>=i]=1
            oof_temp[oof_pred<i]=0
            f1_ = f1_score(y,oof_temp)
            Pscore = precision_score(y,oof_temp)
            Rscore = recall_score(y,oof_temp)
            plt_.loc[n,"num"] = i
            plt_.loc[n,"f1"] = f1_

            if best_f1<f1_:
                best_f1 = f1_
                best_threshold = i
                best_num = len(oof_temp[oof_pred>=i])
                    #print(f"threshold =={i}, f1 score: {f1_},precision_score:{Pscore},recall_score{Rscore}")
        if display:
            plt.plot(plt_['num'],plt_['f1'])
            plt.title('f1_score_with_threshold')
        return best_threshold,best_f1,best_num
    

    train = pd.read_csv(train_path)

    train['is_train'] = 1
    test['is_train'] = 0
    data = train.append(test).reset_index(drop=True)
    data['tlsIssuerDn_null'] = data['tlsIssuerDn'].apply(lambda x:0 if str(x)=='nan' else 1)

    split_col = []
    data['tlsSubject'] = data['tlsSubject'].astype(str).apply(lambda x:x.replace('/',','))

    for string in ['C','ST','L','O','OU','CN']:
        data['tlsSubject_'+string] = data['tlsSubject'].apply(lambda x:''.join([i for i in x.split(',') if string+'=' in i]))
        data['tlsSubject_'+string] = data['tlsSubject_'+string].apply(lambda x:x.split('=')[1] if len(x.split('='))>1 else 'unk')
        split_col.append('tlsSubject_'+string)

    if os.path.exists('cnt_code_dict.pkl'):
        print('baocun')
        for i in split_col+['tlsSubject','tlsIssuerDn','tlsSni','srcAddress','destAddress','tlsVersion',
                  'destPort', 'bytesOut','bytesIn', 'pktsIn', 'pktsOut']:
            cnt_dic = load_feature('cnt_code_dict.pkl')
            data[i+'_cnt'] = data[i].map(cnt_dic[i])
    else:
        cnt_dic = {}
        for i in split_col+['tlsSubject','tlsIssuerDn','tlsSni','srcAddress','destAddress','tlsVersion',
                  'destPort', 'bytesOut','bytesIn', 'pktsIn', 'pktsOut']:
            if i in split_col:
                cnt_dic[i] = data[data['is_train']==1][i].value_counts().to_dict()
            else:
                cnt_dic[i] = train[i].value_counts().to_dict()
            data[i+'_cnt'] = data[i].map(cnt_dic[i])
        save_feature(cnt_dic,'cnt_code_dict.pkl')


    data['bytesOut_pktsIn'] = data['bytesOut'] / data['pktsIn']
    data['bytesIn_pktsOut'] = data['bytesIn'] / data['pktsOut']
    data['bytesIn_bytesOut'] = data['bytesIn'] / data['bytesOut']
    data['pktsIn_pktsOut'] = data['pktsIn'] / data['pktsOut']
    

    data['tlsVersion_num'] = data['tlsVersion'].apply(lambda x:re.findall(r"\d+\.?\d*",x)[0] if len(re.findall(r"\d+\.?\d*",x))==1 else np.nan).astype(float)

    for col in ['tlsSubject_C_cnt', 'tlsSubject_ST_cnt',
     'tlsSubject_L_cnt', 'tlsSubject_O_cnt', 'tlsSubject_OU_cnt',
     'tlsSubject_CN_cnt', 
     'tlsSubject_cnt', 'tlsIssuerDn_cnt', 'tlsSni_cnt',
     'srcAddress_cnt', 'destAddress_cnt', 'tlsVersion_cnt',
     'destPort_cnt', 'bytesOut_cnt', 'bytesIn_cnt',
     'pktsIn_cnt', 'pktsOut_cnt']:
        data[col] = data[col].apply(lambda x:np.nan if x<3 else x)
        
    data['add'] = (data['srcAddress'] + '.' + data['destAddress']).apply(lambda x:x.replace('.',' '))
    tf_df = get_w2v(data, 'add', 8,'vec')
    data = data.merge(tf_df,on='eventId',how='left')
    del data['add']
    
    for i in ['tlsSubject', 'tlsIssuerDn']:
        data[i+'_num'] = data[i].fillna('').apply(lambda x:len(str(x).split(',')))
    for i in ['srcAddress','destAddress']:
        data[i+'_mean'] = data[i].apply(lambda x:np.mean([int(i) for i in x.split('.')]))
        data[i+'_std'] = data[i].apply(lambda x:np.std([int(i) for i in x.split('.')]))
        data[i+'_max'] = data[i].apply(lambda x:np.max([int(i) for i in x.split('.')]))
        data[i+'_min'] = data[i].apply(lambda x:np.min([int(i) for i in x.split('.')]))
    
    #training
    del_col=['tlsSubject','tlsIssuerDn','tlsSni','srcAddress','destAddress','appProtocol', 'tlsVersion',
             'tlsSubject_C', 'tlsSubject_ST', 'tlsSubject_L', 'tlsSubject_OU','tlsSubject_O',
     'tlsSubject_CN']

    train = data[data['is_train'] == 1].reset_index(drop=True)
    test = data[data['is_train'] == 0].reset_index(drop=True)
    
    col=[i for i in train.columns if i not in ['eventId', 'label', 'is_train']+del_col]
    
    X_train=train[col].copy()
    y_train=train['label'].copy().astype(int)
    X_test=test[col].copy()
    print(X_train.shape,X_test.shape)

    lgb_params = {
                            'boosting_type': 'gbdt',
                            'objective': 'binary',
    #                         'metric': 'auc',
                            'num_leaves': 31,
                            'subsample': 0.8,
                            'max_depth':-1,
                            'colsample_bytree': 0.8,
                            'learning_rate': 0.05,
    #                         'bagging_freq':3,
                            'lambda_l2':2,
                            'seed': 1126,
                            'nthread': 8,

                 }

    K =5
    seed = 2021
    skf = StratifiedKFold(n_splits=K, shuffle=True, random_state=seed)
    lgb_models=[]
    oof = np.zeros(len(X_train))
    predictions = np.zeros(len(X_test))
    auc_score = []
    # seeds = [2019]
    seeds = [2019]#,1111,1234
    for j,seed in enumerate(seeds):
                # change seed
        skf.random_state = seed
        lgb_params["seed"] = seed
        #print(j,skf.random_state,lgb_params["seed"])
        for i, (train_index, val_index) in enumerate(skf.split(X_train,y_train)):
            X_tr, X_val = X_train.iloc[train_index], X_train.iloc[val_index]
            y_tr, y_val = y_train.iloc[train_index], y_train.iloc[val_index]

            lgb_train = lgb.Dataset(X_tr,y_tr)
            lgb_val = lgb.Dataset(X_val,y_val)
            num_round = 30000
            if os.path.exists('lgb_'+str(seed)+'_'+str(i)+'.txt'):
                clf = lgb.Booster(model_file='lgb_{}_{}.txt'.format(seed,i))
                #print(i)
            else:
                clf = lgb.train(lgb_params, lgb_train, num_round, valid_sets = [lgb_train, lgb_val],
                                verbose_eval=100, early_stopping_rounds = 60, 
                            #    categorical_feature=cate_feat
                               )#50
                clf.save_model('lgb_{}_{}.txt'.format(seed,i))
            oof[val_index] += clf.predict(X_val, num_iteration=clf.best_iteration)/len(seeds)
            pred = clf.predict(X_val, num_iteration=clf.best_iteration)
            auc_ss = roc_auc_score(y_val, pred)
            auc_score.append(auc_ss)
            #print('auc = ', auc_ss)
            predictions += clf.predict(X_test, num_iteration=clf.best_iteration) / (skf.n_splits*len(seeds))

    best_threshold,best_f1,best_num = find_threshold(oof,y_train,0.1,0.9,display=True,verbose=True)

    sub=test[['eventId']]
    myresult=[1 if x >= best_threshold else 0 for x in predictions]
    sub['label']=[1 if x >= best_threshold else 0 for x in predictions]
    #sub.to_csv('FastCloud_finalA.csv',index = False,encoding='utf-8')
    print(best_threshold)
    return sub['label'][0]

