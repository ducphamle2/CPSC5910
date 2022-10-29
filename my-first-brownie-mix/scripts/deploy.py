from brownie import MyFirstContract, config, accounts
 
def deployContract():
    account = accounts.add(config["wallets"]["from_key"]) or accounts[0]
    MyFirstContract.deploy({'from': account})
 
def main():
    deployContract()
