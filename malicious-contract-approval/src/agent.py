import forta_agent
import rlp
import json
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (
                           TORNADO_CASH_ADDRESSES,
                           TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE,
                           ERC_20_APPROVAL_EVENT_ABI)
from src.findings import SuspiciousContractFindings

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

TORNADO_CASH_FUNDED_ACCOUNTS = []
TORNADO_CASH_MALICIOUS_CONTRACTS = []


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global TORNADO_CASH_FUNDED_ACCOUNTS
    TORNADO_CASH_FUNDED_ACCOUNTS = []

    global TORNADO_CASH_MALICIOUS_CONTRACTS
    TORNADO_CASH_MALICIOUS_CONTRACTS = []


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')

def collect_suspicious_contract_creations(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent):

    update_tornado_cash_funded_accounts(w3, transaction_event)
    # we store the malicious contract in memory
    update_tornado_cash_malicious_contracts(w3, transaction_event)


def detect_approvals_suspicious_contracts(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global TORNADO_CASH_FUNDED_ACCOUNTS
    global TORNADO_CASH_MALICIOUS_CONTRACTS

    findings = []

    # scan through all the addresses involved to find contract addresses among them
    for address in transaction_event.addresses:
        if is_contract(w3, address) == False:
            continue
        approval_events = transaction_event.filter_log(ERC_20_APPROVAL_EVENT_ABI, address)

        # loop through the events to find the spender that matches the malicious contract or account
        for approval_event in approval_events:

            # if there's a spender in tornado account => add into findings
            spender = approval_event['args']['spender']

            if spender in TORNADO_CASH_FUNDED_ACCOUNTS:
                findings.append(SuspiciousContractFindings.suspicious_malicious_account_tornado_cash_approvals(spender, address))

            # if spender in list of malicious contract, add to findings
            for contract_map in TORNADO_CASH_MALICIOUS_CONTRACTS:
                if spender == contract_map['contract_address']:
                    findings.append(SuspiciousContractFindings.suspicious_malicious_contract_tornado_cash_approvals(contract_map['creator_account'], spender, address))
                    continue

    for finding in findings:
        print("finding: ", finding.__dict__)
    return findings

def update_tornado_cash_funded_accounts(w3, transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    this function maintains a list of tornado cash funded accounts; holds up to TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE in memory
    :return: None
    """

    global TORNADO_CASH_FUNDED_ACCOUNTS

    if Web3.toChecksumAddress(transaction_event.from_) not in TORNADO_CASH_ADDRESSES:
        return
    TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(transaction_event.to))

    if len(TORNADO_CASH_FUNDED_ACCOUNTS) <= TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE:
           return
    TORNADO_CASH_FUNDED_ACCOUNTS.pop(0)


def update_tornado_cash_malicious_contracts(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    this function maintains a list of tornado cash malicious contracts mapped with their creators; holds up to TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE in memory
    :return: None
    """

    global TORNADO_CASH_MALICIOUS_CONTRACTS
    global TORNADO_CASH_FUNDED_ACCOUNTS

    tx_hash = transaction_event.hash

    if transaction_event.to is not None:
        return

    if Web3.toChecksumAddress(transaction_event.from_) not in TORNADO_CASH_FUNDED_ACCOUNTS:
        return

    # meaning that this is a transaction deployment tx where transaction_event.to is None, and the from_ was funded by tornado cash
    created_contract_adress = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']

    TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(created_contract_adress))  # needed in case the contract creates another contract
    TORNADO_CASH_MALICIOUS_CONTRACTS.append({'creator_account': transaction_event.from_, 'contract_address': created_contract_adress})
    if len(TORNADO_CASH_MALICIOUS_CONTRACTS) > TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE:
        TORNADO_CASH_MALICIOUS_CONTRACTS.pop(0)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    collect_suspicious_contract_creations(web3, transaction_event)
    return detect_approvals_suspicious_contracts(web3, transaction_event)
