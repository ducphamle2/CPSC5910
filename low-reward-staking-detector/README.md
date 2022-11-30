# Low ERC20 Token Staking Reward Detector

## Description

This detection bot detects when the ERC20 balance of a reward token from a rewarder falls below a certain threshold. It is triggered when the stakers unstake and claim their rewards. This is just a simple POC with basic contracts, but it can be expanded further.

STAKING_CONTRACT_ADDRESS = '0x0a04F8295701F52ee6ec6238424B7A144270E8d4'

REWARDER_ADDRESS = '0x16FF312A4d4171a68a7e06c12916015D30235251'

STAKER_ADDRESS = '0xE05cCbcbCb088D8Ae063401249366348cf0eD6C4'

FAKE_FORTA_ERC20_ADDRESS = '0x4788A901dE8Cb3B1d7461DA4211ef8445bd6FdFA'

REWARD_BALANCE_THRESHOLD = 9999900

# re-fire the event after 5000 blocks if the balance is still below the threshold
ALERT_BLOCK_INTERVAL_CONSTANT = 5000

## Supported Chains

- Polygon

## Alerts

- REWARDER_ERC20_BALANCE_DROP_BELOW_THRESHOLD
  - Fired when the stakers unstake and claim their rewards and the rewarder's balance falls below a certain threshold (currently hardcoded at 9999900 FT).
  - Finding type: Info
  - Finding severity: Info

## Test Data

The agent behaviour can be verified with the following transactions sequentially:

Polygon Mainnet Transactions
- 0x05303f9f5b7e77ce1e6e4a65bc1ffe51c542709d1996689dd99edde8e2d61ada (Init Fake Forta ERC20 token)
- 0xa3292512be1a217f05ef476b317ed4e97c3c15306a97a7a04614d30e6c4b6c1b (Init basic Staking Contract)
- 0xfd46c25c7b3623278d99bb9325e287293e39fd5551cfda7d9691ec968b906664 (Stake transaction)
- 0xddbb2859deb6c9faf8d81563b3f9ae40f0e491ad68a9fed24dc2287232da0f2e (Unstake transaction)

## Commands to test


```bash

# test low balance reward alert
yarn start --tx 0x05303f9f5b7e77ce1e6e4a65bc1ffe51c542709d1996689dd99edde8e2d61ada,0xa3292512be1a217f05ef476b317ed4e97c3c15306a97a7a04614d30e6c4b6c1b,0xfd46c25c7b3623278d99bb9325e287293e39fd5551cfda7d9691ec968b906664,0xddbb2859deb6c9faf8d81563b3f9ae40f0e491ad68a9fed24dc2287232da0f2e
```