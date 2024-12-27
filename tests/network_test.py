from secure_engine.helpers import Network
from dummy_classes import DummyPubKeyServer, DummyUser

def test_network_connect():
    network = Network()
    pks = DummyPubKeyServer()

    user1 = DummyUser('Alice', pks, network)
    network.connect(user1)
    assert user1 in network._users

    user2 = DummyUser('Bob', pks, network)
    network.connect(user2)
    assert user2 in network._users

def test_network_connect_duplicate_user():
    network = Network()
    pks = DummyPubKeyServer()

    user1 = DummyUser('Alice', pks, network)
    network.connect(user1)
    assert user1 in network._users

    network.connect(user1)
    assert len(network._users) == 1

def test_network_send_message():
    network = Network()
    pks = DummyPubKeyServer()

    user1 = DummyUser('Alice', pks, network)
    network.connect(user1)
    n_recipients = network.send_message('Hello, world!')
    assert n_recipients == 1

    user2 = DummyUser('Bob', pks, network)
    network.connect(user2)
    n_recipients = network.send_message('Hello, again!')
    assert n_recipients == 2

def test_network_latest_message():
    network = Network()
    pks = DummyPubKeyServer()
    user1 = DummyUser('Alice', pks, network)
    user2 = DummyUser('Bob', pks, network)

    network.connect(user1)
    network.connect(user2)

    message1 = 'Hello, world!'
    network.send_message(message1)
    assert network.latest_message == message1

    message2 = 'How are you?'
    network.send_message(message2)
    assert network.latest_message == message2