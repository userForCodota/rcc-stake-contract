// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract RccStakeDemo is
Initializable,
UUPSUpgradeable,
PausableUpgradeable,
AccessControlUpgradeable
{
    using SafeERC20 for IERC20;
    using Address for address;
    using Math for uint256;

    // ************************************** 常量 **************************************

    bytes32 public constant ADMIN_ROLE = keccak256("admin_role");
    bytes32 public constant UPGRADE_ROLE = keccak256("upgrade_role");

    uint256 public constant nativeCurrency_PID = 0;

    // ************************************** 数据结构 **************************************
    /*
     基本上，任何时间点，用户有权但待分配的 RCC 数量为：
     待处理的 RCC = (user.stAmount * pool.accRCCPerST) - user.finishedRCC
     每当用户向池中存入或提取质押代币时。发生的情况如下：
     1. 池的“accRCCPerST”（和“lastRewardBlock”）已更新。
     2. 用户收到发送到其地址的待处理 RCC。
     3. 用户的“stAmount”已更新。
     4. 用户的“finishedRCC”已更新。
    */
    struct Pool {
        // 质押代币地址
        address stTokenAddress;
        // Weight of pool 水池重量
        uint256 poolWeight;
        // Last block number that RCCs distribution occurs for pool  // 矿池中 RCC 分配的最后一个区块号
        uint256 lastRewardBlock;
        // Accumulated RCCs per staking token of pool // 池中每个质押代币的累计 RCC
        uint256 accRCCPerST;
        // Staking token amount // 质押代币数量
        uint256 stTokenAmount;
        // Min staking amount // 最小质押金额
        uint256 minDepositAmount;
        // Withdraw locked blocks 撤回锁定的块
        uint256 unstakeLockedBlocks;
    }

    struct UnstakeRequest {
        // Request withdraw amount // 请求提款金额
        uint256 amount;
        // The blocks when the request withdraw amount can be released // 请求提现金额可以释放时的区块
        uint256 unlockBlocks;
    }

    struct User {
        // Staking token amount that user provided // 用户提供的质押代币数量
        uint256 stAmount;
        // Finished distributed RCCs to user // 完成向用户分发 RCC
        uint256 finishedRCC;
        // Pending to claim RCCs // 等待领取 RCC
        uint256 pendingRCC;
        // Withdraw request list // 提款请求列表
        UnstakeRequest[] requests;
    }

    // ************************************** STATE VARIABLES ************************************** 状态变量
    // First block that RCCStake will start from // RCCStake 开始的第一个区块
    uint256 public startBlock;
    // First block that RCCStake will end from // RCCStake 结束的第一个区块
    uint256 public endBlock;
    // RCC token reward per block // 每个区块的 RCC 代币奖励
    uint256 public RCCPerBlock;

    // Pause the withdraw function // 暂停提现功能
    bool public withdrawPaused;
    // Pause the claim function // 暂停领取功能
    bool public claimPaused;

    // RCC token // RCC代币 // 总池权重 所有池权重的总和
    IERC20 public RCC;

    // Total pool weight / Sum of all pool weights // 总池权重 所有池权重的总和
    uint256 public totalPoolWeight;
    Pool[] public pool;

    // pool id => user address => user info
    mapping(uint256 => mapping(address => User)) public user;

    // ************************************** EVENT **************************************

    event SetRCC(IERC20 indexed RCC);

    event PauseWithdraw();

    event UnpauseWithdraw();

    event PauseClaim();

    event UnpauseClaim();

    event SetStartBlock(uint256 indexed startBlock);

    event SetEndBlock(uint256 indexed endBlock);

    event SetRCCPerBlock(uint256 indexed RCCPerBlock);

    event AddPool(address indexed stTokenAddress, uint256 indexed poolWeight, uint256 indexed lastRewardBlock, uint256 minDepositAmount, uint256 unstakeLockedBlocks);

    event UpdatePoolInfo(uint256 indexed poolId, uint256 indexed minDepositAmount, uint256 indexed unstakeLockedBlocks);

    event SetPoolWeight(uint256 indexed poolId, uint256 indexed poolWeight, uint256 totalPoolWeight);

    event UpdatePool(uint256 indexed poolId, uint256 indexed lastRewardBlock, uint256 totalRCC);

    event Deposit(address indexed user, uint256 indexed poolId, uint256 amount);

    event RequestUnstake(address indexed user, uint256 indexed poolId, uint256 amount);

    event Withdraw(address indexed user, uint256 indexed poolId, uint256 amount, uint256 indexed blockNumber);

    event Claim(address indexed user, uint256 indexed poolId, uint256 RCCReward);

    // ************************************** MODIFIER **************************************

    modifier checkPid(uint256 _pid) {
        require(_pid < pool.length, "invalid pid");
        _;
    }

    modifier whenNotClaimPaused() {
        require(!claimPaused, "claim is paused");
        _;
    }

    modifier whenNotWithdrawPaused() {
        require(!withdrawPaused, "withdraw is paused");
        _;
    }

    /**
     * @notice Set RCC token address. Set basic info when deploying. // 设置 RCC 代币地址。部署时设置基本信息。
     */
    function initialize(
        IERC20 _RCC,
        uint256 _startBlock,
        uint256 _endBlock,
        uint256 _RCCPerBlock
    ) public initializer {
        require(_startBlock <= _endBlock && _RCCPerBlock > 0, "invalid parameters");

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPGRADE_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        setRCC(_RCC);

        startBlock = _startBlock;
        endBlock = _endBlock;
        RCCPerBlock = _RCCPerBlock;

    }

    function _authorizeUpgrade(address newImplementation)
    internal
    onlyRole(UPGRADE_ROLE)
    override
    {

    }

    // ************************************** ADMIN FUNCTION ************************************** 管理功能

    /**
     * @notice Set RCC token address. Can only be called by admin // 设置 RCC 代币地址。只能由管理员调用
     */
    function setRCC(IERC20 _RCC) public onlyRole(ADMIN_ROLE) {
        RCC = _RCC;
        emit SetRCC(RCC);
    }

    /**
     * @notice Pause withdraw. Can only be called by admin. // 暂停退出。只能由管理员调用。
     */
    function pauseWithdraw() public onlyRole(ADMIN_ROLE) {
        require(!withdrawPaused, "withdraw has been already paused");
        withdrawPaused = true;
        emit PauseWithdraw();
    }

    /**
     * @notice Unpause withdraw. Can only be called by admin. // 取消暂停提款。只能由管理员调用。
     */
    function unpauseWithdraw() public onlyRole(ADMIN_ROLE) {
        require(withdrawPaused, "withdraw has been already unpaused");

        withdrawPaused = false;

        emit UnpauseWithdraw();
    }

    /**
     * @notice Pause claim. Can only be called by admin. // 暂停索赔。只能由管理员调用。
     */
    function pauseClaim() public onlyRole(ADMIN_ROLE) {
        require(!claimPaused, "claim has been already paused");
        claimPaused = true;
        emit PauseClaim();
    }

    /**
     * @notice Unpause claim. Can only be called by admin. // 取消暂停索赔。只能由管理员调用。
     */
    function unpauseClaim() public onlyRole(ADMIN_ROLE) {
        require(claimPaused, "claim has been already unpaused");
        claimPaused = false;
        emit UnpauseClaim();
    }

    /**
     * @notice Update staking start block. Can only be called by admin. // 更新质押起始块。只能由管理员调用。
     */
    function setStartBlock(uint256 _startBlock) public onlyRole(ADMIN_ROLE) {
        require(_startBlock <= endBlock, "start block must be smaller than end block");

        startBlock = _startBlock;

        emit SetStartBlock(_startBlock);
    }

    /**
     * @notice Update staking end block. Can only be called by admin. // 更新放样结束块。只能由管理员调用。
     */
    function setEndBlock(uint256 _endBlock) public onlyRole(ADMIN_ROLE) {
        require(startBlock <= _endBlock, "start block must be smaller than end block");

        endBlock = _endBlock;

        emit SetEndBlock(_endBlock);
    }

    /**
     * @notice Update the RCC reward amount per block. Can only be called by admin. // 更新每个区块的 RCC 奖励金额。只能由管理员调用。
     */
    function setRCCPerBlock(uint256 _RCCPerBlock) public onlyRole(ADMIN_ROLE) {
        require(_RCCPerBlock > 0, "invalid parameter");

        RCCPerBlock = _RCCPerBlock;

        emit SetRCCPerBlock(_RCCPerBlock);
    }

    /**
     * @notice Add a new staking to pool. Can only be called by admin // 添加新的质押到池中。只能由管理员调用
     * DO NOT add the same staking token more than once. RCC rewards will be messed up if you do // 不要多次添加相同的质押代币。如果这样做，RCC 奖励将会混乱
     */
    function addPool(address _stTokenAddress, uint256 _poolWeight, uint256 _minDepositAmount, uint256 _unstakeLockedBlocks, bool _withUpdate) public onlyRole(ADMIN_ROLE) {
        // Default the first pool to be nativeCurrency pool, so the first pool must be added with stTokenAddress = address(0x0)
        // 默认第一个池为 nativeCurrency 池，因此第一个池必须添加 stTokenAddress = address(0x0)
        if (pool.length > 0) {
            require(_stTokenAddress != address(0x0), "invalid staking token address");
        } else {
            require(_stTokenAddress == address(0x0), "invalid staking token address");
        }
        // allow the min deposit amount equal to 0 // 允许最小存款金额等于 0
        //require(_minDepositAmount > 0, "invalid min deposit amount"); // 允许最小存款金额等于 0
        require(_unstakeLockedBlocks > 0, "invalid withdraw locked blocks");
        require(block.number < endBlock, "Already ended");

        if (_withUpdate) {
            massUpdatePools();
        }

        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalPoolWeight = totalPoolWeight + _poolWeight;

        pool.push(Pool({
            stTokenAddress: _stTokenAddress,
            poolWeight: _poolWeight,
            lastRewardBlock: lastRewardBlock,
            accRCCPerST: 0,
            stTokenAmount: 0,
            minDepositAmount: _minDepositAmount,
            unstakeLockedBlocks: _unstakeLockedBlocks
        }));

        emit AddPool(_stTokenAddress, _poolWeight, lastRewardBlock, _minDepositAmount, _unstakeLockedBlocks);
    }

    /**
     * @notice Update the given pool's info (minDepositAmount and unstakeLockedBlocks). Can only be called by admin.
     // 更新给定池的信息（minDepositAmount 和 unstakeLockedBlocks）。只能由管理员调用。
     */
    function updatePool(uint256 _pid, uint256 _minDepositAmount, uint256 _unstakeLockedBlocks) public onlyRole(ADMIN_ROLE) checkPid(_pid) {
        pool[_pid].minDepositAmount = _minDepositAmount;
        pool[_pid].unstakeLockedBlocks = _unstakeLockedBlocks;
        emit UpdatePoolInfo(_pid, _minDepositAmount, _unstakeLockedBlocks);
    }

    /**
     * @notice Update the given pool's weight. Can only be called by admin. // 更新给定池的权重。只能由管理员调用。
     */
    function setPoolWeight(uint256 _pid, uint256 _poolWeight, bool _withUpdate) public onlyRole(ADMIN_ROLE) checkPid(_pid) {
        require(_poolWeight > 0, "invalid pool weight");

        if (_withUpdate) {
            massUpdatePools();
        }

        totalPoolWeight = totalPoolWeight - pool[_pid].poolWeight + _poolWeight;
        pool[_pid].poolWeight = _poolWeight;

        emit SetPoolWeight(_pid, _poolWeight, totalPoolWeight);
    }

    // ************************************** QUERY FUNCTION ************************************** 查询功能

    /**
     * @notice Get the length/amount of pool // 获取池的长度/数量
     */
    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    /**
     * @notice Return reward multiplier over given _from to _to block. [_from, _to) // 返回给定 _from 到 _to 区块的奖励乘数。[_from, _to)
     *
     * @param _from    From block number (included) // 从区块号（包括）
     * @param _to      To block number (exluded) // 到区块号（排除）
     */
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256 multiplier) {
        require(_from <= _to, "invalid block range");
        if (_from < startBlock) {_from = startBlock;}
        if (_to > endBlock) {_to = endBlock;}
        require(_from <= _to, "end block must be greater than start block");
        bool success;
        (success, multiplier) = (_to - _from).tryMul(RCCPerBlock);
        require(success, "multiplier overflow");
    }

    /**
     * @notice Get pending RCC amount of user in pool // 获取用户在池中的待处理 RCC 金额
     */
    function pendingRCC(uint256 _pid, address _user) external checkPid(_pid) view returns (uint256) {
        return pendingRCCByBlockNumber(_pid, _user, block.number);
    }

    /**
     * @notice Get pending RCC amount of user by block number in pool // 获取用户在池中的待处理 RCC 金额
     */
    function pendingRCCByBlockNumber(uint256 _pid, address _user, uint256 _blockNumber) public checkPid(_pid) view returns (uint256) {
        Pool storage pool_ = pool[_pid];
        User storage user_ = user[_pid][_user];
        uint256 accRCCPerST = pool_.accRCCPerST;
        uint256 stSupply = pool_.stTokenAmount;

        if (_blockNumber > pool_.lastRewardBlock && stSupply != 0) {
            uint256 multiplier = getMultiplier(pool_.lastRewardBlock, _blockNumber);
            uint256 RCCForPool = multiplier * pool_.poolWeight / totalPoolWeight;
            accRCCPerST = accRCCPerST + RCCForPool * (1 ether) / stSupply;
        }

        return user_.stAmount * accRCCPerST / (1 ether) - user_.finishedRCC + user_.pendingRCC;
    }

    /**
     * @notice Get the staking amount of user // 获取用户的质押金额
     */
    function stakingBalance(uint256 _pid, address _user) external checkPid(_pid) view returns (uint256) {
        return user[_pid][_user].stAmount;
    }

    /**
     * @notice Get the withdraw amount info, including the locked unstake amount and the unlocked unstake amount // 获取提款金额信息，包括锁定的提款金额和解锁的提款金额
     */
    function withdrawAmount(uint256 _pid, address _user) public checkPid(_pid) view returns (uint256 requestAmount, uint256 pendingWithdrawAmount) {
        User storage user_ = user[_pid][_user];

        for (uint256 i = 0; i < user_.requests.length; i++) {
            if (user_.requests[i].unlockBlocks <= block.number) {
                pendingWithdrawAmount = pendingWithdrawAmount + user_.requests[i].amount;
            }
            requestAmount = requestAmount + user_.requests[i].amount;
        }
    }

    // ************************************** PUBLIC FUNCTION ************************************** // 公共职能

    /**
     * @notice Update reward variables of the given pool to be up-to-date. // 更新给定池的奖励变量以使其保持最新。
     */
    function updatePool(uint256 _pid) public checkPid(_pid) {
        Pool storage pool_ = pool[_pid];

        if (block.number <= pool_.lastRewardBlock) {
            return;
        }

        (bool success1, uint256 totalRCC) = getMultiplier(pool_.lastRewardBlock, block.number).tryMul(pool_.poolWeight);
        require(success1, "totalRCC mul poolWeight overflow");

        (success1, totalRCC) = totalRCC.tryDiv(totalPoolWeight);
        require(success1, "totalRCC div totalPoolWeight overflow");

        uint256 stSupply = pool_.stTokenAmount;
        if (stSupply > 0) {
            (bool success2, uint256 totalRCC_) = totalRCC.tryMul(1 ether);
            require(success2, "totalRCC mul 1 ether overflow");

            (success2, totalRCC_) = totalRCC_.tryDiv(stSupply);
            require(success2, "totalRCC div stSupply overflow");

            (bool success3, uint256 accRCCPerST) = pool_.accRCCPerST.tryAdd(totalRCC_);
            require(success3, "pool accRCCPerST overflow");
            pool_.accRCCPerST = accRCCPerST;
        }

        pool_.lastRewardBlock = block.number;

        emit UpdatePool(_pid, pool_.lastRewardBlock, totalRCC);
    }

    /**
     * @notice Update reward variables for all pools. Be careful of gas spending! // 更新所有池的奖励变量。小心燃气消耗！
     */
    function massUpdatePools() public {
        uint256 length = pool.length;
        for (uint256 pid = 0; pid < length; pid++) {
            updatePool(pid);
        }
    }

    /**
     * @notice Deposit staking nativeCurrency for RCC rewards  // 存入质押代币以获得 RCC 奖励
     */
    function depositnativeCurrency() public whenNotPaused() payable {
        Pool storage pool_ = pool[nativeCurrency_PID];
        require(pool_.stTokenAddress == address(0x0), "invalid staking token address");

        uint256 _amount = msg.value;
        require(_amount >= pool_.minDepositAmount, "deposit amount is too small");

        _deposit(nativeCurrency_PID, _amount);
    }

    /**
     * @notice Deposit staking token for RCC rewards // 存入质押代币以获得 RCC 奖励
     * Before depositing, user needs approve this contract to be able to spend or transfer their staking tokens // 在存款之前，用户需要批准此合约能够花费或转移他们的质押代币
     *
     * @param _pid       Id of the pool to be deposited to // 要存入的池的 ID
     * @param _amount    Amount of staking tokens to be deposited // 要存入的质押代币数量
     */
    function deposit(uint256 _pid, uint256 _amount) public whenNotPaused() checkPid(_pid) {
        require(_pid != 0, "deposit not support nativeCurrency staking");
        Pool storage pool_ = pool[_pid];
        require(_amount > pool_.minDepositAmount, "deposit amount is too small");

        if (_amount > 0) {
            IERC20(pool_.stTokenAddress).safeTransferFrom(msg.sender, address(this), _amount);
        }

        _deposit(_pid, _amount);
    }

    /**
     * @notice Unstake staking tokens // 取消质押质押代币
     *
     * @param _pid       Id of the pool to be withdrawn from // 要提款的池的 ID
     * @param _amount    amount of staking tokens to be withdrawn // 要提取的质押代币数量
     */
    function unstake(uint256 _pid, uint256 _amount) public whenNotPaused() checkPid(_pid) whenNotWithdrawPaused() {
        Pool storage pool_ = pool[_pid];
        User storage user_ = user[_pid][msg.sender];

        require(user_.stAmount >= _amount, "Not enough staking token balance");

        updatePool(_pid);

        uint256 pendingRCC_ = user_.stAmount * pool_.accRCCPerST / (1 ether) - user_.finishedRCC;

        if (pendingRCC_ > 0) {
            user_.pendingRCC = user_.pendingRCC + pendingRCC_;
        }

        if (_amount > 0) {
            user_.stAmount = user_.stAmount - _amount;
            user_.requests.push(UnstakeRequest({
                amount: _amount,
                unlockBlocks: block.number + pool_.unstakeLockedBlocks
            }));
        }

        pool_.stTokenAmount = pool_.stTokenAmount - _amount;
        user_.finishedRCC = user_.stAmount * pool_.accRCCPerST / (1 ether);

        emit RequestUnstake(msg.sender, _pid, _amount);
    }

    /**
     * @notice Withdraw the unlock unstake amount // 提取解锁的提款金额
     *
     * @param _pid       Id of the pool to be withdrawn from // 要提款的池的 ID
     */
    function withdraw(uint256 _pid) public whenNotPaused() checkPid(_pid) whenNotWithdrawPaused() {
        Pool storage pool_ = pool[_pid];
        User storage user_ = user[_pid][msg.sender];

        uint256 pendingWithdraw_;
        uint256 popNum_;
        for (uint256 i = 0; i < user_.requests.length; i++) {
            if (user_.requests[i].unlockBlocks > block.number) {
                break;
            }
            pendingWithdraw_ = pendingWithdraw_ + user_.requests[i].amount;
            popNum_++;
        }

        for (uint256 i = 0; i < user_.requests.length - popNum_; i++) {
            user_.requests[i] = user_.requests[i + popNum_];
        }

        for (uint256 i = 0; i < popNum_; i++) {
            user_.requests.pop();
        }

        if (pendingWithdraw_ > 0) {
            if (pool_.stTokenAddress == address(0x0)) {
                _safenativeCurrencyTransfer(msg.sender, pendingWithdraw_);
            } else {
                IERC20(pool_.stTokenAddress).safeTransfer(msg.sender, pendingWithdraw_);
            }
        }

        emit Withdraw(msg.sender, _pid, pendingWithdraw_, block.number);
    }

    /**
     * @notice Claim RCC tokens reward // 领取 RCC 代币奖励
     *
     * @param _pid       Id of the pool to be claimed from // 要从中索赔的池的 ID
     */
    function claim(uint256 _pid) public whenNotPaused() checkPid(_pid) whenNotClaimPaused() {
        Pool storage pool_ = pool[_pid];
        User storage user_ = user[_pid][msg.sender];

        updatePool(_pid);

        uint256 pendingRCC_ = user_.stAmount * pool_.accRCCPerST / (1 ether) - user_.finishedRCC + user_.pendingRCC;

        if (pendingRCC_ > 0) {
            user_.pendingRCC = 0;
            _safeRCCTransfer(msg.sender, pendingRCC_);
        }

        user_.finishedRCC = user_.stAmount * pool_.accRCCPerST / (1 ether);

        emit Claim(msg.sender, _pid, pendingRCC_);
    }

    // ************************************** INTERNAL FUNCTION ************************************** 内部功能

    /**
     * @notice Deposit staking token for RCC rewards // 存入质押代币以获得 RCC 奖励
     *
     * @param _pid       Id of the pool to be deposited to // 要存入的池的 ID
     * @param _amount    Amount of staking tokens to be deposited // 要存入的质押代币数量
     */
    function _deposit(uint256 _pid, uint256 _amount) internal {
        Pool storage pool_ = pool[_pid];
        User storage user_ = user[_pid][msg.sender];

        updatePool(_pid);

        if (user_.stAmount > 0) {
            // uint256 accST = user_.stAmount.mulDiv(pool_.accRCCPerST, 1 ether); // user.stAmount * pool.accRCCPerST / 1 ether
            (bool success1, uint256 accST) = user_.stAmount.tryMul(pool_.accRCCPerST);
            require(success1, "user stAmount mul accRCCPerST overflow");
            (success1, accST) = accST.tryDiv(1 ether);
            require(success1, "accST div 1 ether overflow");

            (bool success2, uint256 pendingRCC_) = accST.trySub(user_.finishedRCC);
            require(success2, "accST sub finishedRCC overflow");

            if (pendingRCC_ > 0) {
                (bool success3, uint256 _pendingRCC) = user_.pendingRCC.tryAdd(pendingRCC_);
                require(success3, "user pendingRCC overflow");
                user_.pendingRCC = _pendingRCC;
            }
        }

        if (_amount > 0) {
            (bool success4, uint256 stAmount) = user_.stAmount.tryAdd(_amount);
            require(success4, "user stAmount overflow");
            user_.stAmount = stAmount;
        }

        (bool success5, uint256 stTokenAmount) = pool_.stTokenAmount.tryAdd(_amount);
        require(success5, "pool stTokenAmount overflow");
        pool_.stTokenAmount = stTokenAmount;

        // user_.finishedRCC = user_.stAmount.mulDiv(pool_.accRCCPerST, 1 ether);
        (bool success6, uint256 finishedRCC) = user_.stAmount.tryMul(pool_.accRCCPerST);
        require(success6, "user stAmount mul accRCCPerST overflow");

        (success6, finishedRCC) = finishedRCC.tryDiv(1 ether);
        require(success6, "finishedRCC div 1 ether overflow");

        user_.finishedRCC = finishedRCC;

        emit Deposit(msg.sender, _pid, _amount);
    }

    /**
     * @notice Safe RCC transfer function, just in case if rounding error causes pool to not have enough RCCs // 安全 RCC 转账功能，以防舍入误差导致池中没有足够的 RCC
     *
     * @param _to        Address to get transferred RCCs // 要转移 RCC 的地址
     * @param _amount    Amount of RCC to be transferred // 要转移的 RCC 数量
     */
    function _safeRCCTransfer(address _to, uint256 _amount) internal {
        uint256 RCCBal = RCC.balanceOf(address(this));

        if (_amount > RCCBal) {
            RCC.transfer(_to, RCCBal);
        } else {
            RCC.transfer(_to, _amount);
        }
    }

    /**
     * @notice Safe nativeCurrency transfer function // 安全 nativeCurrency 转账功能
     *
     * @param _to        Address to get transferred nativeCurrency // 要转移 nativeCurrency 的地址
     * @param _amount    Amount of nativeCurrency to be transferred // 要转移的 nativeCurrency 数量
     */
    function _safenativeCurrencyTransfer(address _to, uint256 _amount) internal {
        (bool success, bytes memory data) = address(_to).call{
                value: _amount
            }("");

        require(success, "nativeCurrency transfer call failed");
        if (data.length > 0) {
            require(
                abi.decode(data, (bool)),
                "nativeCurrency transfer operation did not succeed"
            );
        }
    }
}