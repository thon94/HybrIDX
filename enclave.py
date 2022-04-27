import time
import json
import random
from node import Node
from utils import random_binary_string


class Enclave(object):
    def __init__(self, p, k1, k2, prf, node_list):
        self.p = p                      # fixed size of each ciphertext block
        self.k1 = k1                    # secret key 1
        self.k2 = k2                    # secret key 2
        self.prf = prf                  # Pseudo Random Function
        self.F1 = prf(k1)
        self.G1 = prf(k1)
        self.G2 = prf(k2)
        self.node_list = node_list      # list of all nodes to build tree
        self.tree = None                # empty tree
        self.s = 0                      # query session number
        self.__build_tree()             # build tree inside the constructor

    def reset_query_sess(self):
        """
            function to reset query session
        """
        self.s = 0


    def __build_tree(self):
        """
            function to build the enclave binary tree
        """
        for N in self.node_list:
            if self.tree is None:
                self.tree = N
                self.root = N
            else:
                self.tree.insert(N)


    def traverse(self, root):
        """
            function to traverse the entire binary tree
        """
        nodes = []
        if root is not None:
            nodes = self.traverse(root.left)
            nodes.append(root)
            nodes = nodes + self.traverse(root.right)
        return nodes


    def search(self, partkey):
        """
            function to search for a node in the tree given its partkey
        """
        if self.tree is None:
            return None
        else:
            return self.tree.get_node(partkey)


    def insert(self, node):
        """
            function to insert a node into the enclave binary tree
        """
        if self.tree is not None:
            self.tree.insert(node)


    def __dec_token(self, token):
        """
            function to decrypt query token from the client
        """
        # print("Enclave decrypting token from client...")
        self.k0 = self.F1.encrypt(str(self.s))
        token_decoder = self.prf(self.k0)
        raw = token_decoder.decrypt(token)
        self.s += 1
        return raw


    def __get_match_nodes(self, token):
        """
            fucntion to get matched nodes from the query predicate
        """
        # decrypt token from the client
        query = self.__dec_token(token)
        v_query = int(query.split('=')[0][:-1])
        cmp = query.split('=')[0][-1] + '='
        self.cmp = cmp
        q = int(query.split('=')[1])

        # print("Enclave is getting match nodes...")
        all_nodes = self.traverse(self.root)
        all_partkeys = [node.partkey for node in all_nodes]

        # exception handling for the validity of the query predicate
        try:                  # if v_query can match exactly
            match_idx = all_partkeys.index(v_query)
        except ValueError:    # if v_query cannot match exactly
            if v_query < all_partkeys[0] and cmp == ">=":
                match_idx = 0
            elif v_query > all_partkeys[-1] and cmp == "<=":
                match_idx = len(all_partkeys) - 1
            else:
                match_idx = [i for i in range(len(all_partkeys)-1) if all_partkeys[i] < v_query and all_partkeys[i+1] > v_query][0]
                if cmp == ">=":
                    match_idx += 1
        if cmp == ">=":
            n = len(all_nodes) - match_idx
            match_nodes = all_nodes[match_idx : match_idx + q]
        elif cmp == "<=":
            n = match_idx + 1
            left_idx = max(0, match_idx - q + 1)
            match_nodes = all_nodes[left_idx : match_idx+1]
        return match_nodes, n


    def search_query(self, token, Imm, Qsgx):
        """
            function to execute search query
            args:
                token: query token from client
                Imm: untrusted storage
                Qsgx: enclave cache
        """
        match_nodes, n = self.__get_match_nodes(token)
        print("Total number of match nodes:", len(match_nodes))
        res_batch = {}     # to save the batch results

        # process encrypted data for each matched nodes, fetch cipher blocks to client
        for _, node in enumerate(match_nodes):
            res_batch[node.partkey] = []
            res_each_node = []

            # if the current node is already in the cache, fetch from the cache
            if node.partkey in Qsgx.kL_store.keys():   
                L_list = Qsgx.kL_store[node.partkey]
                for L in L_list:
                    V, gamma = Qsgx.LVg_store[L]
                    gamma_star = random_binary_string(4)
                    V_star = [supp_key ^ int(gamma, 2) ^ int(gamma_star, 2) for supp_key in V]
                    res_batch[node.partkey].append((V_star, gamma_star))

            # if current node is not in cache, fetch blocks from untrusted storage
            else:
                if Qsgx.is_full():
                    for partkey in Qsgx.kL_store:
                        self.rebuild(partkey, Qsgx, Imm)
                    Qsgx.clear()
                c = 0
                ci = self.tree.get_node(node.partkey).c
                ti = self.tree.get_node(node.partkey).t
                Qsgx.kL_store[node.partkey] = []
                while c < ci:
                    # get partkey label
                    vi_c_ti = str(node.partkey) + "|" + str(c) + "|" + str(ti)
                    L = self.G1.encrypt(vi_c_ti)
                    # cache vi and label in Qsgx
                    Qsgx.kL_store[node.partkey].append(L)
                    # get block and gamma via Server.Fetch()
                    V, gamma = self.fetch(L, Imm, Qsgx)
                    res_each_node.append((L, V, gamma))
                    c += 1
                Qsgx.current_size += 1
                # self.rebuild(node.partkey, Qsgx, Imm)
                for res in res_each_node:
                    gamma = res[2]
                    V = res[1]
                    gamma_star = random_binary_string(4)
                    V_star = [supp_key ^ int(gamma, 2) ^ int(gamma_star, 2) for supp_key in V]
                    res_batch[node.partkey].append((V_star, gamma_star))
        
        if self.cmp == ">=":
            v_q = match_nodes[-1].partkey
        else:
            v_q = match_nodes[0].partkey
        msg = str(v_q) + "|" + str(n)
        R_encoder = self.prf(self.k0)
        R = R_encoder.encrypt(msg)
        return res_batch, R
    

    def fetch(self, L, Imm, Qsgx):
        """
            fucntion to fetch a cipher block from untrusted storage
            args:
                L: pseudo-label of the block to be fetched
                Imm: untrusted server
                Qsgx: enclave cache
        """
        V, gamma = Imm.get_block(L)
        # cache L, V, gamma in Qsgx
        Qsgx.LVg_store[L] = (V, gamma)
        # delete the block from the untrusted storage
        Imm.del_block(L)
        return V, gamma


    def rebuild(self, partkey, Qsgx, Imm):
        """
            function to rebuild the enclave cache
            args:
                partkey: key to be rebuilt, all blocks of this key will be sent back to the untrusted storage
                Qsgx: enclave cache
                Imm: untrusted server
        """
        # search for the node of the given partkey
        cur_node = self.search(partkey)
        # from the cache, get the list of pseudo-labels of the given partkey
        L_list = Qsgx.kL_store[partkey]
        
        # increment node.t to encrypt new L values
        cur_node.t += 1
        # encrypt cache blocks and send back to the untrusted storage
        c = 0
        for L in L_list:
            V, gamma = Qsgx.LVg_store[L]
            vi_c_ti = str(partkey) + "|" + str(c) + "|" + str(cur_node.t)
            Lp = self.G1.encrypt(vi_c_ti)
            gammap = random_binary_string(4)
            Vp = [s ^ int(gamma, 2) ^ int(gammap, 2) for s in V]
            Imm.set_block(Lp, Vp, gammap)
            c += 1


    def add(self, token, Imm):
        """
            function to insert 
            args:
                token: token from the client
                Imm: untrusted server
        """
        self.k0 = self.F1.encrypt(str(self.s))
        token_decoder = self.prf(self.k0)
        raw_msg = token_decoder.decrypt(token)
        raw_msg_splitted = raw_msg.split("|")
        partkey = int(raw_msg_splitted[0])
        gamma = raw_msg_splitted[1]
        f_new_str = raw_msg_splitted[2]
        f_new_str_list = json.loads(f_new_str)
        f_new_intlist = [int(x, 10) for x in f_new_str_list]
        # print("Need to insert new values for partkey:", partkey, ":", f_new_intlist)
        return self.addData(partkey, gamma, f_new_intlist, self.tree, Imm)


    def get_new_V(self, f_new):
        """
            function to split new cleartext values into equal blocks and encrypt + pad the blocks
            args:
                f_new: new cleartext values
        """
        if len(f_new) % self.p:
            pad_last_block = True
        else:
            pad_last_block = False

        pad_lens = []
        ### total number of ciphertext blocks    
        num_blocks = len(f_new) // self.p + int(pad_last_block)
        new_blocks = []
        ### construct ciphertext blocks for the current range-based index v

        if pad_last_block:
            new_blocks = [f_new[i*self.p : (i+1)*self.p] for i in range(num_blocks-1)]
            last_block = f_new[(num_blocks-1)*self.p :]
            pad_len = self.p-len(last_block)
            pad_values = random.choices(range(1, 10001), k=pad_len)
            last_block += pad_values
            new_blocks.append(last_block)
            pad_lens.extend([0]*(num_blocks-1))
            pad_lens.append(pad_len)
        else:
            new_blocks = [f_new[i*self.p : (i+1)*self.p] for i in range(num_blocks)]
            pad_lens.extend([0]*(num_blocks))
        return new_blocks, pad_lens


    def addData(self, partkey, gamma, f_new, cur_node, Imm):
        """
            function to add new key to the enclave, then add new L-V pairs to the untrusted server
            args:
                partkey: new key to add
                f_new: new values to add
                gamma: random binary string for encryption
                cur_node: current node
                Imm: untrusted server
        """
        if cur_node is not None and cur_node.partkey == partkey:
            c = cur_node.c
            t = cur_node.t
            
            new_blocks, pad_lens = self.get_new_V(f_new)
            new_blocks_L = []
            c_prime = c

            for block in new_blocks:
                v_c_t = str(partkey) + "|" + str(c_prime) + "|" + str(t)
                L = self.G1.encrypt(v_c_t)
                V = [supp_key ^ int(gamma, 2) for supp_key in block]
                c_prime += 1
                Imm.set_block(L, V, gamma)
                new_blocks_L.append(L)

            cur_node.c = c_prime
        elif cur_node is not None and cur_node.partkey < partkey:
            return self.addData(partkey, gamma, f_new, cur_node.right, Imm)
        elif cur_node is not None and cur_node.partkey > partkey:
            return self.addData(partkey, gamma, f_new, cur_node.left, Imm)
        else:
            c_prime = 0

            new_blocks, pad_lens = self.get_new_V(f_new)
            new_blocks_L = []
            for block in new_blocks:
                v_c_t = str(partkey) + "|" + str(c_prime) + "|" + str(0)
                L = self.G1.encrypt(v_c_t)
                V = [supp_key ^ int(gamma, 2) for supp_key in block]
                c_prime += 1
                Imm.set_block(L, V, gamma)
                new_blocks_L.append(L)

            new_node = Node(partkey, c_prime, 0)
            self.tree.insert(new_node)
        return new_blocks_L, pad_lens