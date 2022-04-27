from tqdm import trange
import random
import time
from node import Node
from utils import random_binary_string
from collections import defaultdict
import json
import pandas as pd

class Client():
    def __init__(self, p, k1, k2, prf, gamma_len):
        self.p = p                          # fixed block size
        self.k1 = k1                        # secret key 1
        self.k2 = k2                        # secret key 2
        self.prf = prf                      # pseudo-random function
        self.F1 = prf(k1)
        self.G1 = prf(k1)
        self.G2 = prf(k2)
        self.gamma_len = gamma_len          # len of random binary string for encrypting V
        self.pad_len = defaultdict(list)    # client remembers what is the pad len for each block (zero for unpadded blocks)
        self.node_list = []                 # list of nodes to build the enclave tree
        self.s = 0                          # session number (for querying)
        self.Qres = {}                      # query decrypted results (plaintext)
        self.Qres_undec = {}                # query undecrypted results (ciphertext)
        self.unpadded_keys = []


    def reset_query_sess(self):
        """
            function to reset query session
        """
        self.s = 0
        self.Qres = {}
        self.Qres_undec = {}
        self.unpadded_keys = []


    def preprocess(self, table, progress_bar):
        """
            function to preprocess csv to hash map
            args:
                table: csv data, in numpy array format
                progress_bar: to show the preprocessing progress
            return:
                hashmap: the key-value store in hash map format
        """
        hashmap = {}
        partkey_list = list(set(table[:, 0]))
        for partkey in partkey_list:
            hashmap[partkey] = []
        for i in range(len(table)):
            partkey = table[i, 0]
            hashmap[partkey].append(table[i, 1])
            progress_bar.setValue( int((i+1) / len(table) * 100) )
        return hashmap


    def build(self, table, Imm):
        """
            function to build the untrusted storage from the original dataset
            args:
                table: the original data table
            actions:
                add (L, V, gamma) in terms of hashmap in to the untrusted storage
        """
        start_time = time.time()

        print("Preparing hashmap...")
        k2v = self.preprocess(table)
        print(f"Finish preparing hashmap in {time.time() - start_time} seconds")

        print("Buiding the L-V store for untrusted storage...")
        partkey_list = list(set(table[:, 0]))
        random.shuffle(partkey_list)
        
        indices = trange(len(partkey_list))
        for i, partkey in zip(indices, partkey_list):
            indices.set_description(f"---progress: {i+1}/{len(partkey_list)}")
            self.process_partkey(partkey, Imm, k2v)

        print(f"Finish building L-V store in {time.time() - start_time} seconds")
        

    def process_partkey(self, partkey, Imm, k2v):
        """
            function to encrypt the values of a given partkey into cipher blocks
            args:
                partkey: the key to be encrypted
                Imm: untrusted server
                k2v: the original key-value store in hash map format
        """
        partkey_records = k2v[partkey]

        ### determine whether to pad the last block
        if len(partkey_records) % self.p:
            pad_last_block = True
        else:
            pad_last_block = False

        ### total number of ciphertext blocks
        num_blocks = len(partkey_records) // self.p + int(pad_last_block)
        
        ### construct ciphertext blocks for the current range-based index v
        if pad_last_block:
            partkey_blocks = [partkey_records[i*self.p : (i+1)*self.p] for i in range(num_blocks-1)]
            last_block = partkey_records[(num_blocks-1)*self.p :]
            pad_len = self.p - len(last_block)
            pad_values = random.choices(range(1,10001), k=pad_len)
            last_block = last_block + pad_values
            partkey_blocks.append(last_block)
        else:
            partkey_blocks = [partkey_records[i*self.p : (i+1)*self.p] for i in range(num_blocks)]
            pad_len = 0

        ### generate pseudo labels and encrypt all ciphertext blocks
        for c, block in enumerate(partkey_blocks):
            v_c_t = str(partkey) + "|" + str(c) + "|" + str(0)
            L = self.G1.encrypt(v_c_t)
            gamma = random_binary_string(self.gamma_len)    # random binary string for XOR encryption
            V = [supp_key ^ int(gamma, 2) for supp_key in block]

            if L not in Imm.storage:
                Imm.storage[L] = (V, gamma)

            if c == len(partkey_blocks) - 1:
                self.pad_len[partkey].append(pad_len)
            else:
                self.pad_len[partkey].append(0)

        self.node_list.append( Node(partkey, c+1, 0) )


    def enc_token(self, partkey, cmp, q):
        """
            generate token to send to the enclave
            args:
                partkey: query value
                cmp: order condition, either >= or <= operator
                q: batch size (only pick q first nodes from the range-matched nodes)
        """
        # print("Client is encrypting query predicate...")
        msg = str(partkey) + cmp + str(q)
        self.k0 = self.F1.encrypt(str(self.s))
        token_encoder = self.prf(self.k0)
        token = token_encoder.encrypt(msg)
        self.s += 1
        return token

    def add_token(self, partkey, f_new):
        """
            function to encrypt the insert query predicate
            args:
                partkey: key to be inserted
                f_new: values to be inserted
            return:
                token: token to be sent to the enclave
        """
        # print("Client is encrypting insert query predicate...")
        gamma = random_binary_string(self.gamma_len)
        t_add_msg = str(partkey) + "|" + gamma + "|" + json.dumps(f_new)
        self.k0 = self.F1.encrypt(str(self.s))
        token_encoder = self.prf(self.k0)
        token = token_encoder.encrypt(t_add_msg)
        return token


    def dec_enclave_msg(self, R, res_batch):
        """
            function to decrypt the results fetched by the enclave
            args:
                R: encrypted result size
                res_batch: result batch for the current query
            actions:
                - decrypt the result size and result batch
                - unpad the decrypted blocks to get cleartext results without padded values
        """
        # decrypt result size
        R_decoder = self.prf(self.k0)
        R = R_decoder.decrypt(R)
        # v_q = int(R.split('|')[0])
        n = int(R.split('|')[1])

        print(f"Current batch has {len(res_batch)} partkeys, from partkey {min(res_batch.keys())} to partkey {max(res_batch.keys())}")
        
        # for each of the partkeys, decrypt the blocks associated with that partkey
        for partkey in res_batch:
            if partkey not in self.Qres:
                self.Qres[partkey] = []
                self.Qres_undec[partkey] = []
                for res in res_batch[partkey]:
                    V_star = res[0]
                    gamma_star = res[1]
                    plaintext = [ciphertext ^ int(gamma_star, 2) for ciphertext in V_star]
                    self.Qres[partkey].append(plaintext)
                    self.Qres_undec[partkey].append(V_star)

        # unpad the blocks of all partkeys
        for partkey in self.Qres:
            if partkey not in self.unpadded_keys:
                pad_history = self.pad_len[partkey]
                c = 0
                for block, pad_num in zip(self.Qres[partkey], pad_history):
                    unpadded_block = block[: self.p - pad_num]
                    self.Qres[partkey][c] = unpadded_block
                    c += 1
                self.unpadded_keys.append(partkey)
        return n

    