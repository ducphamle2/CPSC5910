// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts@4.7.3/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts@4.7.3/access/Ownable.sol";
import "@openzeppelin/contracts@4.7.3/utils/cryptography/MerkleProof.sol";

contract SeattleUNFT is ERC721, Ownable {
    bytes32 public root;

    //initialize with "0xcfa14b5b115df11abd5317659a1e4d5d13259641ca7f3b7299dfcbc09b5cdc31"
    constructor(bytes32 _root) ERC721("SeattleU NFT", "SU") {
        root = _root;

    }

    //call with 
    //to: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
    //proof: ["0xf9e19de495b8998dfee29352ebd3bfe146263e1f8b3223187244cf38e03ab9c5","0xe9c363ac8b15db69db1f132015672432dae2ca766a668862d5371379ce145d38"]
    //tokenId: 1
    function safeMint(address to, bytes32[] memory proof, uint256 tokenId) public {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(isValid(proof, leaf), "Not a part of AllowList");
        _safeMint(to, tokenId);
    }

    function isValid(bytes32[] memory proof, bytes32 leaf) public view returns(bool) {
        return MerkleProof.verify(proof, root, leaf);
    }

}
