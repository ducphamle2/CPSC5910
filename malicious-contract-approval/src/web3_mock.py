from hexbytes import HexBytes

EOA_ADDRESS = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'
CONTRACT_NO_ADDRESS = '0x04c90C198b2eFF55716079bc06d7CCc4aa4d7512'
CONTRACT_ERC20 = '0x49A9deCA3DcA86aB3A029C2ed629EC8477009Fee'            


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def get_transaction_count(self, address):
        if address == EOA_ADDRESS:
            return 9
        else:
            return 0

    def get_transaction_receipt(self, hash):
        return {'contractAddress': CONTRACT_NO_ADDRESS}
 
    def get_code(self, address):
        if address == CONTRACT_NO_ADDRESS or address == CONTRACT_ERC20:
            return HexBytes('0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea26469706673582212209a159a4f3847890f10bfb87871a61eba91c5dbf5ee3cf6398207e292eee22a1664736f6c63430008070033')
        elif address == EOA_ADDRESS:
            return HexBytes('0x')
        else:
            return HexBytes('0x')


class ContractMock:
    def __init__(self):
        self.functions = FunctionsMock()

    def __call__(self, address, *args, **kwargs):
        return self


class FunctionsMock:
    def __init__(self):
        self.return_value = None

    def call(self, *_, **__):
        return self.return_value
