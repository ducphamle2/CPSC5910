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
