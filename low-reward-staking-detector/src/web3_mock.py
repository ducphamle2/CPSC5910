from eth_typing import ChecksumAddress

class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

class ContractMock:
    
    def __init__(self):
        self.functions = FunctionsMock()

    def __call__(self, address, *args, **kwargs):
        return self


class FunctionsMock:
    def __init__(self):
        self.return_value = None
    
    def balanceOf(self, address: str):
        self.return_value = 10000
        return self

    def call(self, *_, **__):
        return self.return_value
