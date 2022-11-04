import pytest
from brownie import network
import brownie
import numpy

@pytest.fixture
def timelock(TimeLock, accounts):
    return accounts[0].deploy(TimeLock)

def test_deposit_with_call_data(timelock, accounts):
    block_number = len(network.chain)
    # https://eth-brownie.readthedocs.io/en/stable/api-network.html. Look for Account.transfer
    accounts[0].transfer(timelock, amount=1,data='0x137658380000000000000000000000000000000000000000000000000000000000000001')
    lock_data = timelock.getLock(accounts[0])
    assert lock_data == (1,block_number + 1)

def test_deposit_with_int16_numpy(timelock, accounts):
    block_number = len(network.chain)
    timelock.deposit(numpy.int16(1), {'amount': 1})
    lock_data = timelock.getLock(accounts[0])

    assert lock_data == (1,block_number+1)

def test_deposit_encode_input_int16(timelock, accounts):
    calldata = timelock.deposit.encode_input(numpy.int16(1))
    assert(calldata, '0x137658380000000000000000000000000000000000000000000000000000000000000001')