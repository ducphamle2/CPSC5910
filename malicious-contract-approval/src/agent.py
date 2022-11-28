import forta_agent
import rlp
import json
from forta_agent import get_json_rpc_url, get_transaction_receipt
from hexbytes import HexBytes
from web3 import Web3

from src.constants import (
                           TORNADO_CASH_ADDRESSES,
                           TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE,
                           ERC_20_APPROVAL_EVENT_ABI,
                           TORNADO_WITHDRAW_METHOD_SIGNATURE)
from src.findings import SuspiciousContractFindings

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

TORNADO_CASH_FUNDED_ACCOUNTS = []
TORNADO_CASH_MALICIOUS_CONTRACTS = []

class MyEncoder(json.JSONEncoder):
        def default(self, o):
            return o.__dict__ 


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
    global TORNADO_CASH_FUNDED_ACCOUNTS
    global TORNADO_CASH_MALICIOUS_CONTRACTS

    update_tornado_cash_funded_accounts(w3, transaction_event)
    print("global tornado funded account: ", TORNADO_CASH_FUNDED_ACCOUNTS)
    dequeue_tornado_cash_funded_accounts_list()
    # we store the malicious contract in memory
    update_tornado_cash_malicious_contracts(w3, transaction_event)
    print("global malicious account; ", TORNADO_CASH_MALICIOUS_CONTRACTS)


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
            spender = Web3.toChecksumAddress(approval_event['args']['spender'])
            owner = Web3.toChecksumAddress(approval_event['args']['owner'])

            if Web3.toChecksumAddress(spender) in TORNADO_CASH_FUNDED_ACCOUNTS:
                findings.append(SuspiciousContractFindings.suspicious_malicious_account_tornado_cash_approvals(spender, address))

            # if spender in list of malicious contract, add to findings
            for contract_map in TORNADO_CASH_MALICIOUS_CONTRACTS:
                if spender == contract_map['contract_address']:
                    findings.append(SuspiciousContractFindings.suspicious_malicious_contract_tornado_cash_approvals(contract_map['creator_account'], spender, address))
                    continue
                if owner == contract_map['contract_address']:
                    findings.append(SuspiciousContractFindings.suspicious_malicious_contract_tornado_cash_approvals_contract_is_owner(contract_map['creator_account'], owner, spender, address))

    if len(findings) > 10:
        findings = findings[0:10]
    return findings

def dequeue_tornado_cash_funded_accounts_list():
    global TORNADO_CASH_FUNDED_ACCOUNTS
    if len(TORNADO_CASH_FUNDED_ACCOUNTS) <= TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE:
           return
    TORNADO_CASH_FUNDED_ACCOUNTS.pop(0)

def update_tornado_cash_funded_accounts(w3, transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    this function maintains a list of tornado cash funded accounts; holds up to TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE in memory
    :return: None
    """

    global TORNADO_CASH_FUNDED_ACCOUNTS

    method_signature = transaction_event.transaction.data[0:10]

    # # special case, attackers can withdraw from Tornado Cash to fund their accounts
    if method_signature == TORNADO_WITHDRAW_METHOD_SIGNATURE:
        # position of the recipient, which is the 4th parameter in the withdraw function
        recipient_position_start = 10+64*4
        recipient = f'0x{transaction_event.transaction.data[recipient_position_start:recipient_position_start+64][24:]}'
        # 10:74 is the first parameter of the function, which is the tornado cash address
        # example: https://etherscan.io/tx/0x66b262c0ed24a833d33b6d55a9425908b1a31bbefa33f9f316bd55aa52bf0a94
        tornado_address = f'0x{transaction_event.transaction.data[10:74][24:]}'

        # if recipient is not among the list, maybe it's a false alarm, dont include
        if Web3.toChecksumAddress(tornado_address) not in TORNADO_CASH_ADDRESSES:
            return
        TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(recipient))
        return
    
    # normal case where from is in the TORNADO_CASH_ADDRESSES LIST
    if Web3.toChecksumAddress(transaction_event.from_) in TORNADO_CASH_ADDRESSES:
        TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(transaction_event.to))
        return

    # special case, where the funded account sent funds to another account to start the hack
    if Web3.toChecksumAddress(transaction_event.from_) in TORNADO_CASH_FUNDED_ACCOUNTS and transaction_event.to is not None:
        TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(transaction_event.to))
        return


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
    created_contract_adress = get_transaction_receipt(tx_hash).contract_address

    TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(created_contract_adress))  # needed in case the contract creates another contract
    TORNADO_CASH_MALICIOUS_CONTRACTS.append({'creator_account': Web3.toChecksumAddress(transaction_event.from_), 'contract_address': Web3.toChecksumAddress(created_contract_adress)})
    if len(TORNADO_CASH_MALICIOUS_CONTRACTS) > TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE:
        TORNADO_CASH_MALICIOUS_CONTRACTS.pop(0)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    collect_suspicious_contract_creations(web3, transaction_event)
    return detect_approvals_suspicious_contracts(web3, transaction_event)
