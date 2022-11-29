// // SPDX-License-Identifier: MIT
// pragma solidity >=0.7.0 <0.9.0;

// import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
// import "@openzeppelin/contracts/utils/math/SafeMath.sol";
// import "@openzeppelin/contracts/access/Ownable.sol";

// contract Staking is Ownable {
//     using SafeMath for uint256;
//     IERC20 public rewardToken;
//     struct Lock {
//         uint256 amount;
//         uint256 lockBlock;
//     }

//     mapping(address => Lock) public funds;

//     event Stake(uint256 timelock, uint256 blockNumber);
//     event Unstake(address _address, uint256 amount);

//     constructor(IERC20 _rewardToken) {
//         rewardToken = _rewardToken;
//     }

//     function changeRewardToken(IERC20 _rewardToken) public onlyOwner {
//         rewardToken = _rewardToken;
//     }

//     function stake(uint256 timelock) public payable {
//         require(msg.value > 0, "Eth amount deposited must be greater than 0");

//         // lock the funds
//         funds[msg.sender].amount += msg.value;
//         if (funds[msg.sender].lockBlock < block.number) {
//             funds[msg.sender].lockBlock = block.number + timelock;
//         } else {
//             funds[msg.sender].lockBlock += timelock;
//         }

//         emit Stake(timelock, block.number);
//     }

//     function unstake(uint256 amount) public {
//         require(
//             funds[msg.sender].lockBlock <= block.number,
//             "Current block height must be greater or equal to the lock block"
//         );
//         require(
//             funds[msg.sender].amount > 0,
//             "Lock amount must be greater than 0 to unstake eth"
//         );

//         require(
//             amount <= funds[msg.sender].amount,
//             "unstake amount should be less or equal to your staked amount"
//         );

//         // reset funds data
//         funds[msg.sender].amount -= amount;

//         // transfer reward to staker from token owner. Assume that 1 eth = 1 ERC20 staking token
//         bool result = rewardToken.transferFrom(owner(), msg.sender, amount);
//         if (!result) {
//             revert();
//         }

//         // call to send eth
//         payable(msg.sender).transfer(amount);

//         emit Unstake(msg.sender, amount);
//     }
// }
