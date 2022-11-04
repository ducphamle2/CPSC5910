import pytest
from brownie import network
import brownie

@pytest.fixture
def timelock(TimeLock, accounts):
    return accounts[0].deploy(TimeLock)

def test_get_lock_valid_empty(timelock,accounts):
    assert timelock.getLock(accounts[0]) == (0,0)

# optional parameters including eth passed & sender when invoking a contract: https://eth-brownie.readthedocs.io/en/stable/core-contracts.html#transaction-parameters
# https://eth-brownie.readthedocs.io/en/stable/core-contracts.html#transaction-parameters
def test_timelock_deposit_invalid_eth_amount(timelock):
    with brownie.reverts("Eth amount deposited must be greater than 0"):
        timelock.deposit(1)

def test_timelock_deposit_invalid_not_zero_lock_amount(timelock):
    timelock.deposit(1, {'amount': 1})
    with brownie.reverts("Lock amount should be empty before depositing"):
        timelock.deposit(1)

def test_timelock_deposit_valid_eth_amount_1_locktime_1(timelock,accounts):
    # arrange
    lock_block = 1
    eth_deposit_amount = 1
    block_number = len(network.chain)
    # act
    timelock.deposit(lock_block, {'amount': eth_deposit_amount})
    
    # result
    lock_data = timelock.getLock(accounts[0])
    assert lock_data == (eth_deposit_amount,block_number + lock_block)

def test_timelock_withdraw_invalid_zero_lock_amount(timelock):
    with brownie.reverts("Lock amount must be greater than 0 to withdraw eth"):
        timelock.withdraw()

def test_timelock_withdraw_invalid_lock_block_greater_than_current_block_cannot_withdraw(timelock):
    timelock.deposit(6, {'amount': 1})
    with brownie.reverts("Current block height must be greater or equal to the lock block"):
        timelock.withdraw()

def test_timelock_withdraw_valid_eth_amount_1_locktime_1(timelock,accounts):
    # arrange
    eth_deposit_amount = 1
    # act
    timelock.deposit(1, {'amount': eth_deposit_amount})
    timelock.deposit(1, {'amount': eth_deposit_amount, 'from': accounts[1]})
    timelock.withdraw({'account': accounts[0]})

    # result
    lock_data = timelock.getLock(accounts[0])
    assert lock_data == (0, 0)