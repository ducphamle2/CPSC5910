pragma solidity =0.8.10;

contract TimeLock {
    struct Lock {
        uint256 amount;
        uint256 lockBlock;
    }

    mapping(address => Lock) funds;

    event Deposit(uint256 timelock, uint256 blockNumber);
    event Withdraw(address _address, uint256 amount);

    function deposit(uint64 timelock) external payable {
        // can only deposit when has withdrawn / no lock
        require(funds[msg.sender].amount == 0);
        require(msg.value > 0);

        uint256 timelock256 = uint256(timelock);

        // lock the funds
        funds[msg.sender].amount = msg.value;
        funds[msg.sender].lockBlock = block.number + timelock256;

        emit Deposit(timelock256, block.number);
    }

    function withdraw() external {
        require(funds[msg.sender].lockBlock <= block.number);
        require(funds[msg.sender].amount != 0);

        // temp value to send eth after reset funds
        uint256 amount = funds[msg.sender].amount;

        // reset funds data
        funds[msg.sender].amount = 0;
        funds[msg.sender].lockBlock = 0;

        // call to send eth

        payable(msg.sender).transfer(amount);

        emit Withdraw(msg.sender, amount);
    }

    function getLock(address _address) public view returns (Lock memory) {
        return funds[_address];
    }
}
