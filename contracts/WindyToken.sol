// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract WindyToken is ERC20 {
    constructor(uint initialSupply) ERC20("WindyToken", "WTK") {
        _mint(msg.sender, initialSupply);
    }
}
