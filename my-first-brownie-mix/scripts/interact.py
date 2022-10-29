from brownie import MyFirstContract, config, accounts, network
 
def main():
    account = accounts.add(config["wallets"]["from_key"])
    print("my first contract: ", account)
    myFirstContract = MyFirstContract[-1]
    tx = myFirstContract.setNumber(123456,{'from': account})
    tx.wait(1)
    print("Number is", myFirstContract.getNumber())
