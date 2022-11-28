from forta_agent import create_transaction_event, FindingSeverity
from unittest.mock import Mock
import agent
from findings import SuspiciousContractFindings
from constants import TORNADO_CASH_ADDRESSES
from web3_mock import Web3Mock, CONTRACT_NO_ADDRESS, CONTRACT_ERC20, EOA_ADDRESS


w3 = Web3Mock()


class TestSuspiciousContractAgent:
    def test_is_contract_eoa(self):
        assert not agent.is_contract(w3, EOA_ADDRESS), "EOA shouldn't be identified as a contract"

    def test_is_contract_contract(self):
        assert agent.is_contract(w3, CONTRACT_NO_ADDRESS), "Contract should be identified as a contract"

    def test_update_not_tornado_cash_funded_accounts(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': EOA_ADDRESS,
                'from': EOA_ADDRESS,
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_funded_accounts(w3, tx_event)
        assert len(agent.TORNADO_CASH_FUNDED_ACCOUNTS) == 0, "this address was not funded by tornado cash"

    def test_update_tornado_cash_funded_accounts_success(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'to': EOA_ADDRESS,
                'from': TORNADO_CASH_ADDRESSES[0],
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_funded_accounts(w3, tx_event)
        assert EOA_ADDRESS in agent.TORNADO_CASH_FUNDED_ACCOUNTS, "this address was just funded by tornado cash"

    def test_update_tornado_cash_malicious_contract_creation_fail_to_is_not_none(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'to': EOA_ADDRESS,
                'nonce': 10,
                'contractAddress': '0'
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_malicious_contracts(w3, tx_event)
        assert len(agent.TORNADO_CASH_MALICIOUS_CONTRACTS) == 0

    def test_update_tornado_cash_malicious_contract_creation_fail_creator_not_in_tornado_funded(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
                'contractAddress': '0'
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_malicious_contracts(w3, tx_event)
        assert len(agent.TORNADO_CASH_MALICIOUS_CONTRACTS) == 0

    def test_update_tornado_cash_malicious_contract_creation_success(self):
        agent.initialize()

        self.test_update_tornado_cash_funded_accounts_success()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
                'contractAddress': CONTRACT_NO_ADDRESS
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_malicious_contracts(w3, tx_event)
        print("malicious contracts: ", agent.TORNADO_CASH_MALICIOUS_CONTRACTS)
        assert len(agent.TORNADO_CASH_MALICIOUS_CONTRACTS) == 1
        # increased to 2 because we also add the malicious contract as the funded account from tornado cash, in case it creates a new contract
        assert len(agent.TORNADO_CASH_FUNDED_ACCOUNTS) == 2


    def test_detect_approvals_suspicious_contracts_no_addresses(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding because there was no addresses involved"

    def test_detect_approvals_suspicious_contracts_addresses_are_not_contracts(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'addresses': [EOA_ADDRESS],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding because the addresses are not contracts"

    def test_detect_approvals_suspicious_contracts_addresses_are_not_contracts(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'addresses': [EOA_ADDRESS],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding because the addresses are not contracts"

    def test_detect_approvals_suspicious_contracts_empty_logs(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'addresses': [CONTRACT_NO_ADDRESS],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding because the logs are empty"

    def test_detect_approvals_suspicious_contracts_spender_not_in_funded_accounts(self):
        agent.initialize()

        mock_approval_event = {
            'args': {'owner': EOA_ADDRESS, 'spender': EOA_ADDRESS, 'value': '1'}}

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'addresses': [CONTRACT_NO_ADDRESS],
            'receipt': {
                'logs': []}
        })

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_approval_event]

        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 0, "this should not have triggered a finding because the spender is not in list of tornado cash funded accounts"

    def test_detect_approvals_suspicious_contracts_spender_successful_founded_in_funded_accounts(self):
        agent.initialize()

        self.test_update_tornado_cash_funded_accounts_success()

        mock_approval_event = {
            'args': {'owner': EOA_ADDRESS, 'spender': EOA_ADDRESS, 'value': '1'}}

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'addresses': [CONTRACT_ERC20],
            'receipt': {
                'logs': []}
        })

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_approval_event]

        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 1, "this should trigger because the EOA_ADDRESS belongs in the funded accounts list"
        assert findings[0].description == f'creator {EOA_ADDRESS} funded by Tornado Cash was approved by ERC20 token with address {CONTRACT_ERC20}'

    def test_detect_approvals_suspicious_contracts_spender_successful_founded_in_malicious_contracts(self):
        agent.initialize()

        self.test_update_tornado_cash_malicious_contract_creation_success()

        # mock appoval event to trigger finding
        mock_approval_event = {
            'args': {'owner': EOA_ADDRESS, 'spender': CONTRACT_NO_ADDRESS, 'value': '1'}}

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'addresses': [CONTRACT_ERC20],
            'receipt': {
                'logs': []}
        })

        tx_event.filter_log = Mock()
        tx_event.filter_log.return_value = [mock_approval_event]

        findings = agent.detect_approvals_suspicious_contracts(w3, tx_event)
        assert len(findings) == 2, "this should trigger because CONTRACT_NO_ADDRESS belongs in the malicious contract list, and in the funded account as well"
        assert findings[1].description == f'contract {CONTRACT_NO_ADDRESS} with creator {EOA_ADDRESS} funded by Tornado Cash was approved by ERC20 token with address: {CONTRACT_ERC20}'  


    def test_suspicious_malicious_contract_tornado_cash_approvals(self):
        agent.initialize()

        finding = SuspiciousContractFindings.suspicious_malicious_contract_tornado_cash_approvals("creator", "malicious_contract", "erc20_token")
        assert finding.description == "contract malicious_contract with creator creator funded by Tornado Cash was approved by ERC20 token with address: erc20_token"

    def test_suspicious_malicious_account_tornado_cash_approvals(self):
        agent.initialize()

        finding = SuspiciousContractFindings.suspicious_malicious_account_tornado_cash_approvals("creator", "erc20_token")
        assert finding.description == "creator creator funded by Tornado Cash was approved by ERC20 token with address erc20_token"
