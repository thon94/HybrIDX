

class Qsgx(object):
    def __init__(self, capacity):
        self.capacity = capacity       # capacity of the cache
        self.current_size = 0          # number of keys that the cache is currently holding
        self.LVg_store = {}            # storage of (L, V, gamma)
        self.kL_store = {}             # storage of (partkey, L)


    def get_current_size(self):
        """
            function to get the current size of the cache storage
        """
        return self.current_size


    def is_full(self):
        """
            function to check whether the cache is full
        """
        return self.current_size >= self.capacity


    def clear(self):
        """
            function to clear cache
        """
        self.current_size = 0
        self.LVg_store = {}
        self.kL_store = {}


    def get_from_cache(self, L):
        """
            function to get a ciphertext block given pseudo-label
            args:
                L: pseudo-label to get block from
        """
        return self.LVg_store[L]