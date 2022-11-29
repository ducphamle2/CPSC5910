from forta_agent import Finding, FindingType, FindingSeverity
from src.constants import (FAKE_FORTA_ERC20_ADDRESS, REWARDER_ADDRESS, REWARD_BALANCE_THRESHOLD)


class SuspiciousContractFindings:

    # current balance example: 1000 FT
    @staticmethod
    def rewarder_forta_erc20_balance_drop_below_threshold(current_balance: str) -> Finding:
        return Finding({
            'name': 'Forta ERC20 token balance of Rewarder Has Decreased Below The Threshold',
            'description': f'Forta ERC20 token {FAKE_FORTA_ERC20_ADDRESS} balance of Rewarder {REWARDER_ADDRESS} Has Decreased Below The Threshold. Current balance: {current_balance}. Expected to be above: {REWARD_BALANCE_THRESHOLD}',
            'alert_id': 'REWARDER_ERC20_BALANCE_DROP_BELOW_THRESHOLD',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'protocol': 'polygon'
        })

    @staticmethod
    def rewarder_forta_unexpected_transfer(amount: str, to: str) -> Finding:
        return Finding({
            'name': 'Unexpected transfer Event From The Rewarder Address',
            'description': f'The Rewarder {REWARDER_ADDRESS} Has An Unexpected transfer Event that is not originated from the Unstake Event. The total amount transferred out is: {amount} FT, and it is sent to {to}',
            'alert_id': 'REWARDER_ERC20_BALANCE_UNEXPECTED_TRANSFER',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'protocol': 'polygon'
        })
