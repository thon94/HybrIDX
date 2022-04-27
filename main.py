from PyQt5.QtWidgets import *
from PyQt5 import uic, QtWidgets,QtCore
import pandas as pd
from untrusted import UntrustedStorage
from client import Client
from enclave import Enclave
from prf import PRF
from cache import Qsgx
import sys
import random
import time
import itertools
import sys


class MyGUI(QMainWindow):
    """ GUI object using PyQt5 """
    def __init__(self):
        super(MyGUI, self).__init__()
        uic.loadUi("GUI.ui", self)
        self.show()

        self.Qsgx = Qsgx(capacity=25)       # create a default cache if capacity is not specified

        self.k1 = "rtlZ6JzAq3q8ftuUW3zVuJyd5-NIfzVIVxkK4-6m-vI="
        self.k2 = "GKgkrTc5_EFQmU0mPnMGJRKaC0kJ_az58y0dQNwp52I="

        self.button_browseCSV.clicked.connect(self.browse)
        self.button_create_cache.clicked.connect(self.create_cache)
        self.button_check_cache.clicked.connect(self.check_cache)
        self.button_rebuild_cache.clicked.connect(self.rebuild_cache)
        self.button_build.clicked.connect(self.build_untrusted_and_enclave)
        self.button_exec_query.clicked.connect(self.exec_query)
        self.button_getCiphertext.clicked.connect(self.get_cipher_text)
        self.button_getPlaintext.clicked.connect(self.get_plain_text)
        self.button_getPlaintext_2.clicked.connect(self.get_ground_truth)
        self.button_clear_result.clicked.connect(self.clear_result)
        self.button_insert.clicked.connect(self.insert)

    def browse(self):
        """
            browse csv file
        """
        self.fileName, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Single File', QtCore.QDir.current().path() , '*.csv')
        self.data_name = self.fileName.split('/')[-1].split('.')[0]
        self.box_data_name.setText(self.data_name)

    def create_cache(self):
        """
            function to generate cache (Q_sgx)
            default cache capacity = 25 if not specified by user
        """
        if len(self.Qsgx.kL_store):
            self.rebuild_cache()

        capacity = self.input_capacity.text()
        if capacity == "":
            capacity = 25      # default cache size
        self.Qsgx = Qsgx(int(capacity))
        self.cache_status.setText("Status: Cache capacity changed to {}!".format(capacity))

    def check_cache(self):
        """
            get number of partkeys in the cache (cache.current_size)
        """
        cur_size = self.Qsgx.get_current_size()
        self.box_cache_size.setText("Current size: " + str(cur_size) + '/' + str(self.Qsgx.capacity))


    def build_untrusted_and_enclave(self):
        """
            function to build both the untrust storage and trusted enclave
            actions:
                - build the encrypted key-value (L-V) store in the untrusted storage
                - build enclave binary tree
        """
        data = pd.read_csv(self.fileName, header=None).to_numpy()
        if not str(data[0, 0]).isdecimal():
            data = data[1:]
        data = data.astype(int)
        self.Imm = UntrustedStorage(LV_store={})
        self.client = Client(p=8, k1=self.k1, k2=self.k2, prf=PRF, gamma_len=4)
        self.__client_build(data)
        self.enclave = Enclave(p=8, k1=self.k1, k2=self.k2, prf=PRF, node_list=self.client.node_list)
        print("Finish building HybrIDX!")


    def __client_build(self, table):
        """
            client builds the untrusted storage
            args:
                table: the original key-value store
        """
        start_time = time.time()
        data_name = self.fileName.split('/')[-1].split('.')[0]
        print("Preparing hashmap for {} dataset".format(data_name))
        self.k2v = self.client.preprocess(table, self.progress_hashmap)
        print(f"Finish building hashmap in {time.time() - start_time} seconds")

        print("Buiding the L-V store for untrusted storage...")
        partkey_list = list(set(table[:, 0]))
        self.max_partkey = max(partkey_list)
        self.min_partkey = min(partkey_list)
        random.shuffle(partkey_list)
        for i, partkey in enumerate(partkey_list):
            self.progress_LV.setValue( int((i+1) / len(partkey_list) * 100) )
            self.client.process_partkey(partkey, self.Imm, self.k2v)
        print(f"Finish building L-V store in {time.time() - start_time} seconds")
        # df = pd.DataFrame.from_dict(self.Imm.storage, orient='index')
        # df.reset_index(inplace=True)
        # df.columns = ["label", "cipherblock", "gamma"]
        # df.to_csv('./{}_encrypted.csv'.format(self.data_name), index=False)
        self.__get_all_fake()
        print(f"Size of cleartext database is: {sys.getsizeof(self.k2v) / 1024 / 1024} MB")
        print(f"Size of the encrypted database is: {sys.getsizeof(self.Imm.storage) / 1024 / 1024} MB")

    
    def __update_partkey_range(self):
        """
            function to get the max and min values of all partkeys
        """
        all_partkeys = list( self.k2v.keys() )
        self.max_partkey = max(all_partkeys)
        self.min_partkey = min(all_partkeys)


    def exec_query(self):
        """
            function to execute query
            actions:
                - client encrypts query into token
                - enclave decrypts the token, gets a batch of match nodes, and returns to client
                - client decrypts and unpads the decrypted data from the enclave and untrusted storage
        """
        start_time = time.time()
        v_query = self.v_query.text()
        cmp = self.cmp.currentText()[:2]
        q = self.batch.text()
        if q == "":
            q = 1
            self.batch.setText(str(q))

        self.__update_partkey_range()

        if (int(v_query) > self.max_partkey and cmp == ">=") or (int(v_query) < self.min_partkey and cmp == "<="):
            msg = QMessageBox()
            msg.setWindowTitle("Warning")
            msg.setIcon(QMessageBox.Warning)
            msg.setText("InvalidQuery: query outside range of partkeys.\nPlease try another query.")
            self.all_returned_keys.setText("")
            self.total_match.setText("")
            msg.exec_()
            return
        token = self.client.enc_token(v_query, cmp, q)
        res_batch, res_size = self.enclave.search_query(token, self.Imm, self.Qsgx)

        n = self.client.dec_enclave_msg(res_size, res_batch)
        self.total_match.setText(str(n))
        keys = list(self.client.Qres.keys())
        self.all_returned_keys.setText(str(keys))
        print(f"Done querying in {time.time() - start_time} second")


    def get_cipher_text(self):
        """
            function to get ciphertext of a queried key
            args:
                partkey (from text field)
        """
        partkey = self.query_key.text()
        try:
            msg = str(self.client.Qres_undec[ int(partkey) ])
        except KeyError:
            msg = "Partkey {} is not in the returned results.".format(partkey)
        self.query_ciphertext.setText(msg)


    def get_plain_text(self):
        """
            function to get plaintext of a queried key
            args:
                partkey (from text field)
        """
        partkey = self.query_key.text()
        try:
            msg = self.client.Qres[ int(partkey) ]
            msg = str(list(itertools.chain(*msg)))
        except KeyError:
            msg = "Partkey {} is not in the returned results.".format(partkey)
        self.query_plaintext.setText(msg)


    def get_ground_truth(self):
        """
            function to get ground truth value from the hashmap
            args:
                partkey (from text field)
        """
        partkey = self.query_key.text()
        try:
            msg = str(self.k2v[ int(partkey) ])
            self.true_plaintext.setText(msg)
        except KeyError:
            msg = "Partkey {} does not exist in the database.".format(partkey)
            self.true_plaintext.setText(msg)


    def rebuild_cache(self):
        """
            function to rebuild cache at user's will
            actions:
                - re-encrypt all key in the cache
                - save re-encrypted key-values back to untrusted storage
                - clear cache
        """
        partkeys = list(self.Qsgx.kL_store.keys())
        if len(partkeys) == 0:
            self.cache_status.setText("Status: Cache is empty. Nothing to rebuild!")
            return
        for partkey in partkeys:
            self.enclave.rebuild(partkey, self.Qsgx, self.Imm)
        self.Qsgx.clear()
        self.cache_status.setText("Status: Cache is rebuilt!")


    def clear_result(self):
        """
            function to clear result memory
        """
        self.client.reset_query_sess()
        self.enclave.reset_query_sess()
        self.all_returned_keys.setText("")
        self.total_match.setText("")
        # self.client.Qres = {}
        # self.client.Qres_undec = {}
        # self.client.unpadded_keys = []


    def insert(self):
        """
            insert new values (or both key-values) to the enclave, untrusted storage, cache, and result memory
        """
        key_insert = self.insert_key.text()
        values_insert = self.f_new_list.text()
        values_insert_list = values_insert.split(",")
        
        # insert new key value to hashmap
        try:
            new_int_list = [int(x, 10) for x in values_insert_list]
        except ValueError:
            msg = QMessageBox()
            msg.setWindowTitle("Warning")
            msg.setIcon(QMessageBox.Warning)
            msg.setText("EmptyAdd: Please specify new values.")
            msg.exec_()
            return

        if int(key_insert) in self.k2v:
            for x in new_int_list:
                self.k2v[int(key_insert)].append(x)
        else:
            self.k2v[int(key_insert)] = new_int_list

        self.__update_partkey_range()

        msg = QMessageBox()

        if not hasattr(self,'client') or not hasattr(self,'enclave') or not key_insert.isnumeric() or len(values_insert_list) == 0:
            msg.setWindowTitle("Warning")
            msg.setIcon(QMessageBox.Warning)
            msg.setText("InvalidInsertQuery: insert query failed.\nPlease try another query.")
        else:
            add_token = self.client.add_token(int(key_insert), values_insert_list)
            new_blocks_L, pad_lens = self.enclave.add(add_token, self.Imm)
            self.client.pad_len[int(key_insert)].extend(pad_lens)
            print("Pad lengths for partkey:", key_insert, "->", self.client.pad_len[int(key_insert)])
            if int(key_insert) in self.client.Qres:
                for L, num_pad in zip(new_blocks_L, pad_lens):
                    V, gamma = self.enclave.fetch(L, self.Imm, self.Qsgx)
                    self.Qsgx.kL_store[int(key_insert)].append(L)
                    self.Qsgx.LVg_store[L] = (V, gamma)
                    self.client.Qres_undec[int(key_insert)].append(V)
                    plaintext = [ciphertext ^ int(gamma, 2) for ciphertext in V][: self.client.p - num_pad]
                    self.client.Qres[int(key_insert)].append(plaintext)
                    
            msg.setWindowTitle("Success!")
            msg.setIcon(QMessageBox.Information)
            msg.setText("New data inserted for : " + key_insert)
            # print("New values are inserted successfully for:", key_insert)
            self.f_new_list.setText("")
        msg.exec_()


    def __get_all_fake(self):
        """
            function to get the number of fake values in the database
        """
        count = 0
        for v in self.client.pad_len.values():
            count += sum(v)
        print('total number of fake values: ', count)



def main():
    app = QApplication([])
    window = MyGUI()
    window.setWindowTitle("HybrIDX Program")
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()