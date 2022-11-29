# Low ERC20 Token Staking Reward Detector

## Description

This detection bot detects when the ERC20 balance of a reward token from a rewarder falls below a certain threshold. It is triggered when the stakers unstake and claim their rewards. This is just a simple POC with basic contracts, but it can be expanded further.

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

## Command to test
`yarn start --tx 0x05303f9f5b7e77ce1e6e4a65bc1ffe51c542709d1996689dd99edde8e2d61ada,0xa3292512be1a217f05ef476b317ed4e97c3c15306a97a7a04614d30e6c4b6c1b,0xfd46c25c7b3623278d99bb9325e287293e39fd5551cfda7d9691ec968b906664,0xddbb2859deb6c9faf8d81563b3f9ae40f0e491ad68a9fed24dc2287232da0f2e`