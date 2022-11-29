from forta_agent import create_transaction_event, FindingSeverity
from unittest.mock import Mock
import agent
from findings import SuspiciousContractFindings
from constants import (
    REWARDER_ADDRESS,
    FAKE_FORTA_ERC20_ADDRESS,
    STAKER_ADDRESS,
    ZERO_ADDRESS,
    REWARD_BALANCE_THRESHOLD,
    STAKING_CONTRACT_ADDRESS,
    TRANSFER_EVENT_ABI,
)
from web3_mock import Web3Mock


w3 = Web3Mock()


class TestSuspiciousContractAgent:

    def test_get_rewarder_erc20_balance(self):
        transaction_event = create_transaction_event({
            'block': {
                'number': 1
            }}
        )
        agent.get_rewarder_erc20_balance(w3,transaction_event)
        assert agent.REWARDER_TOTAL_ERC20_BALANCE == 10000

        # when the same block number, we wont continue querying
        agent.get_rewarder_erc20_balance(w3,transaction_event)
        assert agent.REWARDER_TOTAL_ERC20_BALANCE == 10000

        # when different block number, we will again try querying
        transaction_event = create_transaction_event({
            'block': {
                'number': 2
            }}
        )
        agent.get_rewarder_erc20_balance(w3,transaction_event)
        assert agent.REWARDER_TOTAL_ERC20_BALANCE == 10001

    
    def test_increase_rewarder_erc20_balance(self):
        # first case, 'from' is non-zero => dont increase balance of rewarder
        mock_mint_event = {
            'args': {'from': REWARDER_ADDRESS, 'to': STAKER_ADDRESS, 'value': 1}}

        tx_event = create_transaction_event({
            'block': {
                'number': 0
            },
        })

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_mint_event]

        agent.increase_rewarder_erc20_balance(w3, tx_event)

        assert agent.REWARDER_TOTAL_ERC20_BALANCE, 0

        # second case, success
        mock_mint_event = {
            'args': {'from': ZERO_ADDRESS, 'to': REWARDER_ADDRESS, 'value': 1}}

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_mint_event]

        agent.increase_rewarder_erc20_balance(w3, tx_event)

        assert agent.REWARDER_TOTAL_ERC20_BALANCE, 1
    
    def test_decrease_rewarder_erc20_balance(self):

        # init to 3, and then we try decreasing
        agent.REWARDER_TOTAL_ERC20_BALANCE = 3

        # first case, no event => no decrease
        tx_event = create_transaction_event({
            'block': {
                'number': 0
            },
        })
        agent.decrease_rewarder_erc20_balance(w3, tx_event)
    
        assert agent.REWARDER_TOTAL_ERC20_BALANCE, 3

        # second case, successful
        mock_mint_event = {
            'args': {'_address': STAKER_ADDRESS, 'amount': 1}}

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_mint_event, mock_mint_event]

        agent.decrease_rewarder_erc20_balance(w3, tx_event)
    
        assert agent.REWARDER_TOTAL_ERC20_BALANCE, 1

    def test_notify_rewarder_erc20_balance_below_threshold(self):

        agent.REWARDER_TOTAL_ERC20_BALANCE = REWARD_BALANCE_THRESHOLD + 2
        
        # first case, balance still larger or equal to balance threshold => no findings
        tx_event = create_transaction_event({
            'block': {
                'number': 0
            },
            'logs': [
                {
                    'address': STAKING_CONTRACT_ADDRESS,
                    STAKING_CONTRACT_ADDRESS: True
                }
            ]
        })
        # second case, successful
        mock_unstake_event = {
            'args': {'_address': STAKER_ADDRESS, 'amount': 1}}

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_unstake_event, mock_unstake_event]

        findings = agent.notify_rewarder_erc20_balance_below_threshold(w3, tx_event)

        assert len(findings) == 0

        # second case, successful
        findings = agent.notify_rewarder_erc20_balance_below_threshold(w3, tx_event)

        assert len(findings) == 1

    def test_unexpected_FT_token_rewarder_transfer(self):
        # first case, wrong event or from is not REWARDER ADDRESS => will not return any findings
        tx_event = create_transaction_event({
            'block': {
                'number': 0
            },
            'logs': [
                {
                    'address': STAKING_CONTRACT_ADDRESS,
                    STAKING_CONTRACT_ADDRESS: True
                }
            ]
        })
        mock_unstake_event = {
            'args': {'_address': STAKER_ADDRESS, 'amount': 1}}

        mock_transfer_event = {
            'args': {'from': STAKER_ADDRESS, 'to': REWARDER_ADDRESS, 'value': 1}}

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_unstake_event,mock_transfer_event]

        findings = agent.unexpected_transfer_rewarder(w3, tx_event)

        assert len(findings) == 0