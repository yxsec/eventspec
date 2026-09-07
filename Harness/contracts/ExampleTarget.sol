// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExampleTarget {
    event Transfer(address indexed from, address indexed to, uint256 value);

    function emitTransfer(address from, address to, uint256 value) external {
        emit Transfer(from, to, value);
    }
}
