Usage
=====

.. _installation:

Installation
------------

To use the Encrypted Communication package, first install it using pip:

.. code-block:: console

   (.venv) $ pip install encrypted-communication

Sending a message
-----------------

To send a message, you need to create a :py:class:`encrypted_comm.user.User` 
object, that can then send a message to other users.

The users must have unique names, be registered to a public key server, and be
connected to a common network to be able to communicate.

For example::

   >>> from encrypted_comm.user import User
   >>> from encrypted_comm.helpers import PubKeyServer, Network

   >>> pks = PubKeyServer()
   >>> network = Network()
   >>> Bob = User('Bob', pks, network)
   >>> Alice = User('Alice', pks, network)
   >>> Charlie = User('Charlie', pks, network)
   
   Starting user "Bob"...
   User "Bob" started.

   Starting user "Alice"...
   User "Alice" started.

   Starting user "Charlie"...
   User "Charlie" started.

This will start three users, Bob, Alice and Charlie, on the same network, and
register them to the public key server.

Now, Bob can send a message to Alice::

   >>> Bob.send('Hello, Alice!', 'Alice')

   User "Alice" received message:
      Sender: Bob (verified)
      Message timestamp: 20231216-185210.230840
      Message age: 65.857 ms: Accepted.
      Message type: `session_request`. Sending response.

   User "Bob" received message:
      Sender: Alice (verified)
      Message timestamp: 20231216-185210.361188
      Message age: 65.377 ms: Accepted.
      Message type: `session_response`. Sending session info.

   User "Alice" received message:
      Sender: Bob (verified)
      Message timestamp: 20231216-185211.320340
      Message age: 65.8 ms: Accepted.
      Session open with Bob. Session ID: Z3oMb_3BXh

   User "Alice" received message:
      Sender: Bob (verified)
      Message timestamp: 20231216-185211.386060
      Message age: 69.62 ms: Accepted.
      Verified message: Hello, Alice!

Once a session is open, Alice can reply with a single message::

   >>> Alice.send('Hi Bob!', 'Bob')

   User "Bob" received message:
	Sender: Alice (verified)
	Message timestamp: 20231216-185218.624037
	Message age: 65.281 ms: Accepted.
	Verified message: Hi Bob!
