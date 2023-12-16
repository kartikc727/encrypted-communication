"""Helper classes and functions for the encrypted_communication module.
"""

import json

class Network:
    """
    A class representing a network of users.

    Attributes:
        _users (list): A list of connected users.
        _latest_message (str): The latest message sent in the network.

    Methods:
        connect(user): Connects a user to the network.
        send_message(message): Sends a message to all connected users.
    """

    def __init__(self):
        """
        Initializes a Network object with an empty list of users and no latest message.
        """
        self._users = []
        self._latest_message = None

    def connect(self, user:'User'):
        """
        Connects a user to the network.

        Args:
            user (User): The user to connect.

        Returns:
            None
        """
        if user in self._users:
            return

        self._users.append(user)

    def send_message(self, message:str):
        """
        Sends a message to all connected users.

        Args:
            message (str): The message to send.

        Returns:
            int: The number of users who received the message.
        """
        num_received = 0
        for user in self._users:
            return_code = user.receive(message)
            if return_code == 0:
                num_received += 1

        self._latest_message = message
        return num_received
    
    @property
    def latest_message(self)->str:
        """
        Gets the latest message sent in the network.

        Returns:
            str: The latest message.
        """
        return self._latest_message

class PubKeyServer:
    """
    A class representing a public key server.

    Attributes:
        _keys (dict): A dictionary mapping usernames to public keys.

    Methods:
        register(user): Registers a user's public key.
        __call__(username): Retrieves a user's public key.
    """

    def __init__(self):
        """
        Initializes a PubKeyServer object with an empty dictionary of keys.
        """
        self._keys = dict()

    def register(self, user:'User'):
        """
        Registers a user's public key.

        Args:
            user (User): The user to register.

        Returns:
            None
        """
        self._keys[user.username] = user.public_key

    def __call__(self, username)->bytes:
        """
        Retrieves a user's public key.

        Args:
            username (str): The username of the user.

        Returns:
            str: The public key of the user.
        """
        return self._keys[username]

class MultiKeyDict:
    """
    A class representing a dictionary with multiple keys.

    Attributes:
        _keys (tuple): A tuple of key names.
        _data (dict): A dictionary of dictionaries, where each key in _keys maps to a dictionary of items.
        _len (int): The number of items in the MultiKeyDict.

    Methods:
        add(item): Adds an item to the MultiKeyDict.
        __getitem__(key): Retrieves an item from the MultiKeyDict using a key.
        __delitem__(key): Deletes an item from the MultiKeyDict using a key.
        __contains__(key): Checks if an item is present in the MultiKeyDict using a key.
        __len__(): Returns the number of items in the MultiKeyDict.
        __str__(): Returns a string representation of the MultiKeyDict.
        __repr__(): Returns a string representation of the MultiKeyDict.
    """

    def __init__(self, *key_names):
        """
        Initializes a MultiKeyDict object with the specified key names.

        Args:
            *key_names (str): The names of the keys.

        Raises:
            ValueError: If no key names are provided.
        """
        if len(key_names) == 0:
            raise ValueError('MultiKeyDict needs at least one key')
        self._keys = key_names
        self._data = {k : dict() for k in key_names}
        self._len = 0
        
    def add(self, item:dict):
        """
        Adds an item to the MultiKeyDict.

        Args:
            item (dict): The item to add.

        Raises:
            ValueError: If the item has partial presence of keys or if the keys of multiple different items are being set.

        Returns:
            None
        """
        has_key = [(k, item[k]) in self for k in self._data]
        
        # Item should either already be present, with all keys set
        if all(has_key):
            # Check they are all pointing to the same item
            k = self._keys[0]
            curr_item = self._data[k][item[k]]
            
            for k_ in self._keys:
                if self._data[k_][item[k_]] is not curr_item:
                    raise ValueError('Attempting to set keys of multiple different items')
        
        # Or item should not be present at all
        elif any(has_key):
            raise ValueError('Item has partial presence of keys')
            
        for k in self._data:
            self._data[k][item[k]] = item
            
    def __getitem__(self, key):
        """
        Retrieves an item from the MultiKeyDict using a key.

        Args:
            key (tuple): The key to use for retrieval.

        Raises:
            KeyError: If the item is not found.

        Returns:
            dict: The retrieved item.
        """
        key_name, key_val = key
        try:
            return self._data[key_name][key_val]
        except KeyError:
            raise KeyError(f'{key_name} : {key_val}')
    
    def __delitem__(self, key):
        """
        Deletes an item from the MultiKeyDict using a key.

        Args:
            key (tuple): The key to use for deletion.

        Returns:
            None
        """
        key_name, key_val = key
        item = self._data[key_name][key_val]
        for k in self._keys:
            del self._data[k][item[k]]
            
    def __contains__(self, key):
        """
        Checks if an item is present in the MultiKeyDict using a key.

        Args:
            key (tuple): The key to check.

        Returns:
            bool: True if the item is present, False otherwise.
        """
        key_name, key_val = key
        return key_val in self._data[key_name]
    
    def __len__(self):
        """
        Returns the number of items in the MultiKeyDict.

        Returns:
            int: The number of items.
        """
        return len(self._data[self._keys[0]])
        
    def __str__(self):
        """
        Returns a string representation of the MultiKeyDict.

        Returns:
            str: The string representation.
        """
        try:
            return json.dumps(self._data, indent=4)
        except TypeError:
            return str(self._data)
    
    def __repr__(self):
        """
        Returns a string representation of the MultiKeyDict.

        Returns:
            str: The string representation.
        """
        return repr(self._data)
