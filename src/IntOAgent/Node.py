class Node:
    def __init__(self, name):
        self.name = name  # Node name
        self.body = None
        self.parent = None  # Parent node
        self.children = []  # List of child nodes

    def get_parent(self):
        """Get the parent node of the current node"""
        return self.parent

    def set_body(self, body):
        self.body = body

    def add_child(self, child):
        """Add a child node"""
        child.parent = self  # Set the parent of the child node
        self.children.append(child)
    
    def set_parent(self, parent):
        self.parent = parent
    
    def remove_child(self, child):
        """
        Remove a child node from the current node.
        
        Args:
            child (Node): The child node to be removed.
        
        Raises:
            ValueError: If the child node is not found in the current node's children.
        """
        if child in self.children:
            self.children.remove(child)  # Remove the child from the children list
            child.parent = None  # Update the parent reference of the child node
        else:
            raise ValueError(f"Child node '{child.name}' not found in the current node's children.")

    def get_path_to_root_funcname(self):
        """Get the path from the current node to the root node by function name"""
        path = [self.name]
        current_node = self
        while current_node.parent:
            current_node = current_node.parent
            path.insert(0, current_node.name)  # Add the parent node to the front of the path
        return path

    def get_path_to_root_funcbody(self):
        path = [self.body]
        current_node = self
        while current_node.parent:
            current_node = current_node.parent
            path.insert(0,current_node.body)  # Add the parent node's body to the front of the path
        return path

    def get_root_name(self):
        """Get the name of the root node"""
        current_node = self
        while current_node.parent:
            current_node = current_node.parent
        return current_node.name