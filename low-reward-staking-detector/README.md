# Rewarder balance listener

flow: create global var holding rewarder's balance
get current balance
then if top-up => increase
if unstake => decrease
below threshold => alert

yarn start --tx 0x05303f9f5b7e77ce1e6e4a65bc1ffe51c542709d1996689dd99edde8e2d61ada,0xa3292512be1a217f05ef476b317ed4e97c3c15306a97a7a04614d30e6c4b6c1b,0xfd46c25c7b3623278d99bb9325e287293e39fd5551cfda7d9691ec968b906664,0xddbb2859deb6c9faf8d81563b3f9ae40f0e491ad68a9fed24dc2287232da0f2e