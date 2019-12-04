import numpy as np
import argparse
import os
import json
import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.naive_bayes import MultinomialNB
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn import tree

import target as api
from GoAuditParser import *


class MLModule:
    """
    A Machine Learning Module for predicting whether or not a batch of syscalls is malicious.

    To train the model, execute the following command "python3 MLModule.py --train"

        This will train on data from default path '../train_data/malicious' and '../train_data/non-malicious'
        To change the path of the data for training, use arguments --malicious_path [path of malicious folder]
        and --non_malicious_path [path of non-malicious folder]

    To run the model, execute the following command "python3 MLModule.py --run"

        Similar to --train, you can specify path if you wish.

    To train and run, use both arguments '--train' and '--run'

    To specify batch size, add argument --batch_size [int size]

    To specify seed size, add argument --seed [int size]

    To specify model, add argument --model [model name]
    Note: Default model is is gnb, can specify either gnb, mnb, or dtree

    Currently, the model that we fit to is the Gaussian Naive Bayes model.

    TODO: Add implementation for live data stream from GoAuditParser
    TODO: Add multiple types of classifiers
    TODO: Classify batches live

    """

    gnb_file = 'model_params/gnb.joblib'
    mnb_file = 'model_params/mnb.joblib'
    dtree_file = 'model_params/dtree.joblib'
    pca_file = 'model_params/pca.joblib'
    lgr_file = 'model_params/lgr.joblib'

    def __init__(self, model):
        self.model = model

    def train_module(self, x_train, y_train):
        gnb = GaussianNB()
        mnb = MultinomialNB()
        dtree = tree.DecisionTreeClassifier()
        pca = PCA()
        lgr = LogisticRegression()

        gnb.fit(x_train, y_train)
        mnb.fit(x_train, y_train)
        dtree.fit(x_train, y_train)
        pca.fit_transform(x_train)
        lgr.fit(pca.transform(x_train)[:, 0:100], y_train)

        joblib.dump(gnb, self.gnb_file)
        joblib.dump(mnb, self.mnb_file)
        joblib.dump(dtree, self.dtree_file)
        joblib.dump(pca, self.pca_file)
        joblib.dump(lgr, self.lgr_file)

    def run_module(self, x_val, y_val, model):
        if model == 'gnb':
            gnb = joblib.load(self.gnb_file)
            gnby_pred = gnb.predict(x_val)
            print("Predicted " + str((y_val != gnby_pred).sum()) + "/" + str(x_val.shape[0]) +
              " of validation data incorrectly. Gaussian Naive Bayes has accuracy: " +
              str(1 - (y_val != gnby_pred).sum() / float(x_val.shape[0])))

        if model == 'mnb':
            mnb = joblib.load(self.mnb_file)
            mnby_pred = mnb.predict(x_val)
            print("Predicted " + str((y_val != mnby_pred).sum()) + "/" + str(x_val.shape[0]) +
              " of validation data incorrectly. Multinomial Naive Bayes has accuracy: " +
              str(1 - (y_val != mnby_pred).sum() / float(x_val.shape[0])))

        if model == 'dtree':
            dtree = joblib.load(self.dtree_file)
            dtreey_pred = dtree.predict(x_val)
            print("Predicted " + str((y_val != dtreey_pred).sum()) + "/" + str(x_val.shape[0]) +
              " of validation data incorrectly. DecisionTreeClassifier has accuracy: " +
              str(1 - (y_val != dtreey_pred).sum() / float(x_val.shape[0])))

        if model == 'lgr':
            pca = joblib.load(self.pca_file)
            lgr = joblib.load(self.lgr_file)
            lgry_pred = lgr.predict(pca.transform(x_val)[:, 0:100])
            print("Predicted " + str((y_val != lgry_pred).sum()) + "/" + str(x_val.shape[0]) +
                  " of validation data incorrectly. Logistic Regression has accuracy: " +
                  str(1 - (y_val != lgry_pred).sum() / float(x_val.shape[0])))

    def all_data(self, malicious_fp, non_malicious_fp, batch_size, train_split, seed):
        data_m, labels_m, comms_m = self.get_data(malicious_fp, 1, batch_size=batch_size)  # , "VirusShare")
        data_n, labels_n, comms_n = self.get_data(non_malicious_fp, 0, batch_size=batch_size)

        data, labels = self.shuffle_data(np.concatenate([data_m, data_n]), np.concatenate([labels_m, labels_n]), seed)
        data = self.get_counts(data)
        x_train, y_train, x_val, y_val = self.split_data(data, labels, train_split)
        return x_train, y_train, x_val, y_val

    def get_data(self, path, label, comm="", batch_size=64):
        all_batches = []
        all_labels = []
        all_comms = []
        for file in os.listdir(path):
            file_path = path + '/' + file
            input_file = open(file_path)
            json_array = json.load(input_file)
            store_list = []
            for item in json_array:
                if comm in item['comm']:
                    store_details = {"syscall": item['syscall'], "comm": item['comm']}
                    store_list.append(store_details)
            comms = [[d['comm']] for d in store_list]
            data = [np.array(int(d['syscall'])) for d in store_list]
            data = np.array(data)

            batches = []
            labels = []
            for i in range(int(len(data) / batch_size)):
                batches.append(data[i * batch_size:(i + 1) * batch_size])
                labels.append(label)
            all_comms.extend(comms)
            all_batches.extend(batches)
            all_labels.extend(labels)
        all_batches = np.array(all_batches)
        all_labels = np.array(all_labels)
        return all_batches, all_labels, comms

    def shuffle_data(self, data, labels, seed):
        np.random.seed(seed)
        rng_state = np.random.get_state()
        np.random.shuffle(data)
        np.random.set_state(rng_state)
        np.random.shuffle(labels)
        return data, labels

    def split_data(self, X, y, split=0.75):
        x_train = X[0:int(len(X) * split)]
        y_train = y[0:int(len(y) * split)]
        x_val = X[int(len(X) * split):len(X)]
        y_val = y[int(len(y) * split):len(y)]
        return x_train, y_train, x_val, y_val

    def get_counts(self, data):
        new_trains = []
        for i in range(len(data)):
            x = data[i]
            new_train = np.zeros(394 + 1)
            for j in range(len(x)):
                call = x[j]
                new_train[call] += 1
            new_trains.extend([new_train])
        return np.array(new_trains)

    def live_stream(self, batch):
        wanted = ['syscall']
        self.classify(dataParseStream(batch, wanted))

    def classify(self, parsed):
        inp = self.get_counts(np.array(parsed).T)
        self.run_m(inp, self.model)

    def run_m(self, x_val, model):
        if model == 'gnb':
            gnb = joblib.load(self.gnb_file)
            y_pred = gnb.predict(x_val)
            if y_pred == np.array([1]):
                print("malicious")
            else:
                print("benign")
        if model == 'mnb':
            mnb = joblib.load(self.mnb_file)
            y_pred = mnb.predict(x_val)
            if y_pred == np.array([1]):
                print("malicious")
            else:
                print("benign")

        if model == 'dtree':
            dtree = joblib.load(self.dtree_file)
            y_pred = dtree.predict(x_val)
            if y_pred == np.array([1]):
                print("malicious")
            else:
                print("benign")

        if model == 'lgr':
            pca = joblib.load(self.pca_file)
            lgr = joblib.load(self.lgr_file)
            y_pred = lgr.predict(pca.transform(x_val)[:, 0:100])
            if y_pred == np.array([1]):
                print("malicious")
            else:
                print("benign")


# Run main function
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='code')
    parser.add_argument('--train', action="store_true", default=False)
    parser.add_argument('--run', action="store_true", default=False)
    parser.add_argument('--malicious_path', type=str, default='../train_data/malicious',
                        help='path to malicious data txt file')
    parser.add_argument('--non_malicious_path', type=str, default='../train_data/non-malicious',
                        help='path to non-malicious data txt file')
    parser.add_argument('--batch_size', type=int, default=128)
    parser.add_argument('--train_split', type=float, default=0.75)
    parser.add_argument('--seed', type=int, default=59)
    parser.add_argument('--model', type=str, default='dtree')
    args = parser.parse_args()

    ml_mod = MLModule(args.model)

    x_train, y_train, x_val, y_val = ml_mod.all_data(
        malicious_fp=args.malicious_path,
        non_malicious_fp=args.non_malicious_path,
        batch_size=args.batch_size,
        train_split=args.train_split,
        seed=args.seed
    )
    if args.train is True:
        ml_mod.train_module(x_train, y_train)
        ml_mod.run_module(x_val,y_val, args.model)
    if args.run is True:
        api.getContinuousBatches(128, ml_mod.live_stream, False)
