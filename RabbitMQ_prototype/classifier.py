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

import glassboxAPI as api
from GoAuditParser import *


class MLModule:
    """
    Authors: Ben Colebrook, Tarush Sinha
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
    Note: Default model is is dtree, can specify either gnb, mnb, dtree, or lgr


    """

    gnb_file = 'model_params/gnb.joblib'
    mnb_file = 'model_params/mnb.joblib'
    dtree_file = 'model_params/dtree.joblib'
    pca_file = 'model_params/pca.joblib'
    lgr_file = 'model_params/lgr.joblib'

    MAX_SYSCALL_NUM = 394

    def __init__(self, model, pc):
        """
        The constructor for the ML Module class.
        :param model: the type of model we would like to use
        """
        self.model = model
        self.pc = pc

    def train(self, x_train, y_train):
        """
        Train the module on Gaussian Naive Bayes, Multinomial Naive Bayes, Decision Tree, and PCA/Logistic Regression
        models.

        The parameters of the fit model are stored in joblib files.

        :param x_train: training data
        :param y_train: training labels
        :return: void
        """
        gnb = GaussianNB()
        mnb = MultinomialNB()
        dtree = tree.DecisionTreeClassifier()
        pca = PCA()
        lgr = LogisticRegression()

        gnb.fit(x_train, y_train)
        mnb.fit(x_train, y_train)
        dtree.fit(x_train, y_train)
        pca.fit_transform(x_train)
        lgr.fit(pca.transform(x_train)[:, 0:self.pc], y_train)

        joblib.dump(gnb, self.gnb_file)
        joblib.dump(mnb, self.mnb_file)
        joblib.dump(dtree, self.dtree_file)
        joblib.dump(pca, self.pca_file)
        joblib.dump(lgr, self.lgr_file)

    def validate(self, x_val, y_val, model):
        """
        Run the module on data with the model chosen.
        :param x_val: validation data
        :param y_val:
        :param model:
        :return:
        """
        if model == 'gnb':
            gnb = joblib.load(self.gnb_file)
            y_pred = gnb.predict(x_val)
            print("Predicted " + str((y_val != y_pred).sum()) + "/" + str(x_val.shape[0]) +
                  " of validation data incorrectly. Gaussian Naive Bayes has accuracy: " +
                  str(1 - (y_val != y_pred).sum() / float(x_val.shape[0])))

        if model == 'mnb':
            mnb = joblib.load(self.mnb_file)
            y_pred = mnb.predict(x_val)
            print("Predicted " + str((y_val != y_pred).sum()) + "/" + str(x_val.shape[0]) +
                  " of validation data incorrectly. Multinomial Naive Bayes has accuracy: " +
                  str(1 - (y_val != y_pred).sum() / float(x_val.shape[0])))

        if model == 'dtree':
            dtree = joblib.load(self.dtree_file)
            y_pred = dtree.predict(x_val)
            print("Predicted " + str((y_val != y_pred).sum()) + "/" + str(x_val.shape[0]) +
                  " of validation data incorrectly. DecisionTreeClassifier has accuracy: " +
                  str(1 - (y_val != y_pred).sum() / float(x_val.shape[0])))

        if model == 'lgr':
            pca = joblib.load(self.pca_file)
            lgr = joblib.load(self.lgr_file)
            y_pred = lgr.predict(pca.transform(x_val)[:, 0:self.pc])
            print("Predicted " + str((y_val != y_pred).sum()) + "/" + str(x_val.shape[0]) +
                  " of validation data incorrectly. Logistic Regression has accuracy: " +
                  str(1 - (y_val != y_pred).sum() / float(x_val.shape[0])))

    def all_data(self, malicious_fp, non_malicious_fp, batch_size, train_split, seed):
        """
        Gets the data from the two file paths and creates batches of the data.
        The batches are of length batch_size.
        The train/test split is train_split/(1-train_split).
        The seed is used for shuffling the data.
        :param malicious_fp: folder that contains malicious logs
        :param non_malicious_fp: folder that contains non-malicious logs
        :param batch_size: batch size
        :param train_split: train split
        :param seed: random seed
        :return: training and validation data and labels.
        """
        data_m, labels_m, comms_m = self.get_data(malicious_fp, 1, exe="VirusShare", batch_size=batch_size)  # , "VirusShare")
        data_n, labels_n, comms_n = self.get_data(non_malicious_fp, 0, batch_size=batch_size)
        print("Malicious dataset shape {}.".format(data_m.shape))
        print("Non-malicious dataset shape {}.".format(data_n.shape))

        data, labels = self.shuffle_data(np.concatenate([data_m, data_n]), np.concatenate([labels_m, labels_n]), seed)
        data = self.get_counts(data)
        _x_train, _y_train, _x_val, _y_val = self.split_data(data, labels, train_split)
        return _x_train, _y_train, _x_val, _y_val

    def get_data(self, path, label, exe="", batch_size=64):
        """
        Get the data from a specific file path
        :param path: path of folder which contains the data
        :param label: label the data 1 for malicious, 0 for non-malicious
        :param exe: the "comm" to filter the data by
        :param batch_size: batch size wanted
        :return: the batches, labels, and comms
        """
        all_batches = []
        all_labels = []
        all_exes = []
        for file in os.listdir(path):
            file_path = path + '/' + file
            input_file = open(file_path)
            json_array = json.load(input_file)
            store_list = []
            for item in json_array:
                if exe in item['comm']:
                    store_details = {"syscall": item['syscall'], "exe": item['comm']}
                    store_list.append(store_details)
            exes = [[d['exe']] for d in store_list]
            data = [np.array(int(d['syscall'])) for d in store_list]
            data = np.array(data)

            batches = []
            labels = []
            for i in range(int(len(data) / batch_size)):
                batches.append(data[i * batch_size:(i + 1) * batch_size])
                labels.append(label)
            all_exes.extend(exes)
            all_batches.extend(batches)
            all_labels.extend(labels)
        all_batches = np.array(all_batches)
        all_labels = np.array(all_labels)
        return all_batches, all_labels, all_exes

    def shuffle_data(self, data, labels, seed):
        """
        Shuffle the data and labels by seed for reproduction.
        :param data: data to be shuffled
        :param labels: labels to be shuffled
        :param seed: random seed
        :return: shuffled data and labels
        """
        np.random.seed(seed)
        rng_state = np.random.get_state()
        np.random.shuffle(data)
        np.random.set_state(rng_state)
        np.random.shuffle(labels)
        return data, labels

    def split_data(self, x, y, split=0.75):
        """
        Split data for train and validation sets.
        :param X: data to be split
        :param y: labels
        :param split: percentage of train split
        :return: training and validation data and labels
        """
        _x_train = x[0:int(len(x) * split)]
        _y_train = y[0:int(len(y) * split)]
        _x_val = x[int(len(x) * split):len(x)]
        _y_val = y[int(len(y) * split):len(y)]
        return _x_train, _y_train, _x_val, _y_val

    def get_counts(self, data):
        """
        Get the counts of each syscall in each batch
        :param data: array of batches
        :return: array of array with count at index of syscall number
        """
        new_trains = []
        for i in range(len(data)):
            x = data[i]
            new_train = np.zeros(self.MAX_SYSCALL_NUM + 1)
            for j in range(len(x)):
                call = x[j]
                new_train[call] += 1
            new_trains.extend([new_train])
        return np.array(new_trains)

    def get_count(self, batch):
        """
        Get counts of single batch.
        :param batch: single batch
        :return: array with counts at index of syscall number
        """
        counts = np.zeros(self.MAX_SYSCALL_NUM + 1)
        for j in range(len(batch)):
            call = batch[j]
            counts[call] += 1
        return np.array(counts)

    def classify_live(self, batch):
        """
        Callback function for API
        :param batch: receives batch
        :return:
        """
        wanted = ['syscall']
        unparsed = dataParseStream(batch, wanted)
        to_int = [int(item[0]) for item in unparsed]
        parsed = np.array(to_int).T
        data = self.get_count(parsed).reshape(1, -1)
        batch_ip = batch[0]['interfaces'][0]['network_data'][0]['ip']
        batch_exe = batch[0]['exe']
        self.run_model(data, self.model, batch_exe, batch_ip)

    def run_model(self, data, model, exe, ip='localhost'):
        """
        Run prediction on models
        :param data: data
        :param model: model
        :param exe: exe for printing
        :return:
        """
        y_pred = []

        if model == 'gnb':
            gnb = joblib.load(self.gnb_file)
            y_pred = gnb.predict(data)

        if model == 'mnb':
            mnb = joblib.load(self.mnb_file)
            y_pred = mnb.predict(data)

        if model == 'dtree':
            dtree = joblib.load(self.dtree_file)
            y_pred = dtree.predict(data)

        if model == 'lgr':
            pca = joblib.load(self.pca_file)
            lgr = joblib.load(self.lgr_file)
            y_pred = lgr.predict(pca.transform(data)[:, 0:self.pc])

        if y_pred == np.array([1]):
            print("{:10s}\t{:20s}\t{}".format("malicious", ip, exe))
        elif y_pred == np.array([0]):
            print("{:10s}\t{:20s}\t{}".format("benign", ip, exe))


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
    parser.add_argument('--pc', type=int, default=100, help='number of principle components to use in pca')
    args = parser.parse_args()

    ml_mod = MLModule(args.model, args.pc)

    if args.train is True:
        print("Training........")
        x_train, y_train, x_val, y_val = ml_mod.all_data(
            malicious_fp=args.malicious_path,
            non_malicious_fp=args.non_malicious_path,
            batch_size=args.batch_size,
            train_split=args.train_split,
            seed=args.seed
        )
        ml_mod.train(x_train, y_train)
        ml_mod.validate(x_val, y_val, args.model)
    if args.run is True:
        api.getUniqueContBatches(args.batch_size, ml_mod.classify_live)
