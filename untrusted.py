

class UntrustedStorage(object):
    def __init__(self, LV_store):
        self.storage = LV_store

    def get_block(self, L):
        """
            function to get ciphertext block from pseudo-label
            args: 
                L: pseudo-label of the block
            return:
                V: ciphertext block
                gamma: the binary string to decrypt V
        """
        try:
            V = self.storage[L][0]
            gamma = self.storage[L][1]
            return V, gamma
        except KeyError:
            print("Pseudo-label is not correct. Cannot access the cipher block!")


    def set_block(self, L, V_new, gamma_new):
        """
            function to set new value for a ciphertext block
            args:
                L: pseudo-label of the block
                V_new: list of new values for the block
        """
        # assert len(V_new) == self.p, "new value list should have length {}".format(self.p)
        self.storage[L] = (V_new, gamma_new)


    def del_block(self, L):
        """
            function to delete a block from the storage using its label
            args:
                L: label of the deleted block
        """
        try:
            del self.storage[L]
        except KeyError:
            print("Wrong label, cannot delete cipherblock.")