import forta_agent
import rlp
import json
from forta_agent import get_json_rpc_url
from web3 import Web3
from web3.contract import Contract

from src.constants import (
    UNSTAKE_EVENT_ABI,STAKING_CONTRACT_ADDRESS,FAKE_FORTA_ERC20_ADDRESS,REWARD_BALANCE_THRESHOLD,FORTA_ERC20_CONTRACT_ABI, REWARDER_ADDRESS,TRANSFER_EVENT_ABI,ZERO_ADDRESS,
    ALERT_BLOCK_INTERVAL_CONSTANT
)
from src.findings import SuspiciousContractFindings

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

REWARDER_TOTAL_ERC20_BALANCE = 0
CURRENT_HANDLING_BLOCK_NUMBER = 0
ALERT_BLOCK_INTERVAL = 0
HAS_FIRED_ALERT = False

class MyEncoder(json.JSONEncoder):
        def default(self, o):
            return o.__dict__ 


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global REWARDER_TOTAL_ERC20_BALANCE
    global CURRENT_HANDLING_BLOCK_NUMBER
    global ALERT_BLOCK_INTERVAL
    global HAS_FIRED_ALERT
    REWARDER_TOTAL_ERC20_BALANCE = 0
    CURRENT_HANDLING_BLOCK_NUMBER = 0
    ALERT_BLOCK_INTERVAL = 0
    HAS_FIRED_ALERT = False


def get_fake_forta_erc20_token_contract(w3: Web3) -> Contract:

    # abi of forta erc20 token
    abi=json.loads(FORTA_ERC20_CONTRACT_ABI)

    contract = w3.eth.contract(Web3.toChecksumAddress(FAKE_FORTA_ERC20_ADDRESS), abi=abi)
    return contract

def get_rewarder_erc20_balance(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    this function returns the erc20 forta token balance of the rewarder 
    :return: total balance in integer
    """

    global REWARDER_TOTAL_ERC20_BALANCE
    global CURRENT_HANDLING_BLOCK_NUMBER

    contract = get_fake_forta_erc20_token_contract(w3)
    block_number = transaction_event.block.number
    
    # we dont query the rewarder balance over and over again in the same block, because it will potentially reset the balance count within the same block but different txs
    if block_number == CURRENT_HANDLING_BLOCK_NUMBER:
        return
    print("transaction event block number: ", transaction_event.block.number)
    REWARDER_TOTAL_ERC20_BALANCE = contract.functions.balanceOf(REWARDER_ADDRESS).call(block_identifier=transaction_event.block.number)
    print("rewarder balance of: ", REWARDER_TOTAL_ERC20_BALANCE)

def increase_rewarder_erc20_balance(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent):

    """
    this function parses Events that send more FT tokens to the Rewarder Address, either from mint() or transfer() or transferFrom()
    We do this to reduce the load of querying rewarder balances through RPC.
    """

    global REWARDER_TOTAL_ERC20_BALANCE

    # get mint function then collect the amount to increase the rewarder total balance
    events = transaction_event.filter_log(TRANSFER_EVENT_ABI, FAKE_FORTA_ERC20_ADDRESS)
    
    for event in events:
        if 'from' not in event['args'] or 'to' not in event['args']:
            continue
        if event['args']['to'] != REWARDER_ADDRESS:
            continue
        # a correct transfer event to increase the balance of the rewarder address
        REWARDER_TOTAL_ERC20_BALANCE += event['args']['value']

def decrease_rewarder_erc20_balance(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent):

    """
    this function parses the Unstake Event that transfer FT tokens from Rewarder address to other addresses in a form of unstaking
    """

    global REWARDER_TOTAL_ERC20_BALANCE

    unstake_events = transaction_event.filter_log(UNSTAKE_EVENT_ABI, STAKING_CONTRACT_ADDRESS)
    if len(unstake_events) == 0:
        return []
    for unstake_event in unstake_events:

        if 'amount' not in unstake_event['args']:
            continue

        amount = unstake_event['args']['amount']
        print("unstake amount: ", amount)

        REWARDER_TOTAL_ERC20_BALANCE -= amount
    
    return unstake_events

def count_alert_interval(transaction_event: forta_agent.transaction_event.TransactionEvent) -> bool:
    global ALERT_BLOCK_INTERVAL
    global CURRENT_HANDLING_BLOCK_NUMBER

    print("current alert block interval: ", ALERT_BLOCK_INTERVAL)
    print("current handling block number: ", CURRENT_HANDLING_BLOCK_NUMBER)
    print("transaction event block number in count alert interval: ", transaction_event.block.number)

    if CURRENT_HANDLING_BLOCK_NUMBER == transaction_event.block.number:
        return False

    if ALERT_BLOCK_INTERVAL == 0:
        ALERT_BLOCK_INTERVAL += 1
        return True

    ALERT_BLOCK_INTERVAL += 1
    if ALERT_BLOCK_INTERVAL < ALERT_BLOCK_INTERVAL_CONSTANT:
        return False
    ALERT_BLOCK_INTERVAL = 0
    return False


def notify_rewarder_erc20_balance_below_threshold(w3: Web3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:

    """
    This function calls filter events to increase and decrease the rewarder balance respectively, and fire an alert if the rewarder's FT token balance reduces below the REWARD_BALANCE_THRESHOLD value
    """

    global REWARDER_TOTAL_ERC20_BALANCE
    global CURRENT_HANDLING_BLOCK_NUMBER

    findings = []

    increase_rewarder_erc20_balance(w3, transaction_event)
    decrease_rewarder_erc20_balance(w3, transaction_event)

    if REWARDER_TOTAL_ERC20_BALANCE < REWARD_BALANCE_THRESHOLD:
        low_balance_should_alert = count_alert_interval(transaction_event)
        print("low balance should restart: ", low_balance_should_alert)
        if low_balance_should_alert is True:
            findings.append(SuspiciousContractFindings.rewarder_forta_erc20_balance_drop_below_threshold(f'{REWARDER_TOTAL_ERC20_BALANCE} FT'))

    # reset current handling block number to the latest block after processing everything
    if CURRENT_HANDLING_BLOCK_NUMBER != transaction_event.block.number:
         CURRENT_HANDLING_BLOCK_NUMBER = transaction_event.block.number
    return findings


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    get_rewarder_erc20_balance(web3, transaction_event)
    return notify_rewarder_erc20_balance_below_threshold(web3, transaction_event)