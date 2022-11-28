from forta_agent import Finding, FindingType, FindingSeverity


class SuspiciousContractFindings:

    @staticmethod
    def parse_erc20_tokens_in_findings(erc20_tokens: set) -> object:
        return {"address_contained_in_created_contract_" + str(i): address for i, address in enumerate(erc20_tokens, 1)}

    @staticmethod
    def suspicious_malicious_contract_tornado_cash_approvals(creator: str, contract_address: str, erc20_token: str) -> Finding:
        return Finding({
            'name': 'Suspicious Contract created by Tornado Cash funded account with ERC20 token Approval',
            'description': f'contract {contract_address} with creator {creator} funded by Tornado Cash was approved by ERC20 token with address: {erc20_token}',
            'alert_id': 'SUSPICIOUS-CONTRACT-APPROVAL-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
        })

    @staticmethod
    def suspicious_malicious_contract_tornado_cash_approvals_contract_is_owner(creator: str, contract_address: str, spender: str, erc20_token: str) -> Finding:
        return Finding({
            'name': 'Suspicious Contract created by Tornado Cash funded account with ERC20 token Approval as Owner',
            'description': f'contract {contract_address} with creator {creator} funded by Tornado Cash approved {spender} to spend ERC20 token with address: {erc20_token}',
            'alert_id': 'SUSPICIOUS-CONTRACT-APPROVAL-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
        })

    @staticmethod
    def suspicious_malicious_account_tornado_cash_approvals(creator: str, erc20_token: str) -> Finding:
        return Finding({
            'name': 'Suspicious Tornado Cash funded account ERC20 token Approval',
            'description': f'creator {creator} funded by Tornado Cash was approved by ERC20 token with address {erc20_token}',
            'alert_id': 'SUSPICIOUS-ACCOUNT-APPROVAL-TORNADO-CASH',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
        })
