// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const {buildModule} = require("@nomicfoundation/hardhat-ignition/modules");

const INITIAL_SUPPLY = 1_000_000n; // 1,000,000 WTK (以 wei 为单位)

module.exports = buildModule("WindyTokenModule", (m) => {
    const initialSupply = m.getParameter("initialSupply", INITIAL_SUPPLY);
    const windyToken = m.contract("WindyToken", [initialSupply]);
    return {windyToken};
});
