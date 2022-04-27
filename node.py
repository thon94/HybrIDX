

class Node:
    def __init__(self, partkey, c, t):
        self.left = None
        self.right = None
        self.partkey = partkey
        self.c = c
        self.t = t

    def insert(self, new_node):
        if new_node.partkey < self.partkey:
            if self.left is None:
                self.left = new_node
            else:
                self.left.insert(new_node)
        elif new_node.partkey > self.partkey:
            if self.right is None:
                self.right = new_node
            else:
                self.right.insert(new_node)

    def get_node(self, part_key): # Pritam
        if part_key == self.partkey:
            return self
        elif self.left != None and part_key < self.partkey:
            return self.left.get_node(part_key)
        elif self.right != None and part_key > self.partkey:
            return self.right.get_node(part_key)
        return None

    def __get_node_info(self):
        print(f"Node partkey: {self.partkey}, c||t = {self.c}||{self.t}")
        if self.left:
            print(f"   --left child: {self.left.partkey}, c||t = {self.left.c}||{self.left.t}")
        else:
            print(f"   --left child: None")
        if self.right:
            print(f"   --right child: {self.right.partkey}, c||t = {self.right.c}||{self.right.t}\n")
        else:
            print(f"   --right child: None\n")

    def print_tree(self):
        if self.left:
            self.left.print_tree()

        self.__get_node_info()

        if self.right:
            self.right.print_tree()