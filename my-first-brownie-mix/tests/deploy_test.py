import pytest

@pytest.fixture
def timelock(TimeLock, accounts):
    return accounts[0].deploy(TimeLock)

def test_get_lock_valid_empty(timelock,accounts):
    assert timelock.getLock(accounts[0]) == (0,0)

def test_timelock_deposit_invalid_amount(timelock,accounts):
    timelock.deposit(1)