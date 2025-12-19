# Valid Findings:

## DoS in `SuperDCAListing::collectFees` when Uniswap V4 pool involves native ETH

### Severity
High

### Summary
The `collectFees` function assumes both tokens in a pool are ERC20s and calls `IERC20.balanceOf` on them. If the pool uses a native token (ETH on Ethereum, MATIC on Polygon, BNB on BNB chain, etc.), this results in `IERC20(address(0)).balanceOf(...)` which reverts, making it impossible to collect fees from native token pairs.

### Root Cause
The function `collectFees` in (`https://github.com/sherlock-audit/2025-09-super-dca-PavelPindarev/blob/main/super-dca-gauge/src/SuperDCAListing.sol#L292-L332`) snapshots ERC20 balances unconditionally:

```solidity
uint256 balance0Before = IERC20(Currency.unwrap(token0)).balanceOf(recipient);
uint256 balance1Before = IERC20(Currency.unwrap(token1)).balanceOf(recipient);
```

In Uniswap V4, `Currency` can represent native ETH (`Currency.wrap(address(0))`). 
When a currency is native token (ETH/MATIC/etc.), `Currency.unwrap(...)` returns `address(0)`, causing `IERC20(address(0)).balanceOf(...)` to revert.
As a result, `collectFees` always reverts for native token pools, blocking fee collection.

### Internal Pre-conditions
A native token pool (e.g., ETH/DCA on Ethereum or MATIC/DCA on Polygon) has been listed in `SuperDCAListing`.

### External Pre-conditions

### Attack Path
1. The native token/DCA pool NFP is custody-transferred into `SuperDCAListing` during normal onboarding (`list(nftId, poolKey)`).
2. Traders swap in the native/DCA pool; fees accumulate in Uniswap’s internal accounting for that NFP.
3. The protocol owner calls `SuperDCAListing.collectFees(nftId, recipient)` to sweep fees to `recipient`.
4. `collectFees` snapshots balances by calling `IERC20(...).balanceOf(...)`. For native ETH this becomes `IERC20(address(0)).balanceOf(...)` and reverts.
5. The `collectFees` call fails and fees remain trapped (Denial of Service).

### Impact
- Denial of Service: Fees from native token pools cannot be collected by the owner.
- Protocol Revenue Blocked: Revenue from pools like ETH/DCA on Ethereum or MATIC/DCA on Polygon is permanently stuck.
  
### PoC
Place the following contract in `super-dca-gauge/test/SuperDCAListing.t.sol` file.
Run by this command `forge test --mt test_CollectFeesNative_Reverts` in the console.

```solidity
contract CollectFeesNative is SuperDCAListingTest {
    function setUp() public override {
        // Override super setup
        // Tokens
        address nativeETH = address(0);
        dcaToken = new MockERC20Token("Super DCA Token", "SDCA", 18);
        // Deploy core Uniswap V4
        deployFreshManagerAndRouters();

        Deployers.deployMintAndApprove2Currencies();
        bytes memory p2code = new Permit2Bytecode().getBytecode();
        address p2addr = makeAddr("permit2");
        vm.etch(p2addr, p2code);
        permit2 = IAllowanceTransfer(p2addr);
        posM = new PositionManager(
            IPoolManager(address(manager)), permit2, 5000, IPositionDescriptor(address(0)), IWETH9(address(weth))
        );
        positionManagerV4 = IPositionManager(address(posM));
        listing = new SuperDCAListing(address(dcaToken), manager, positionManagerV4, developer, IHooks(address(0)));

        // Build a pool key with NativeETH/DCA
        key = super._createPoolKey(nativeETH, address(dcaToken), LPFeeLibrary.DYNAMIC_FEE_FLAG);
        poolId = key.toId();

        IHooks hook = SuperDCAListingTest._deployHook();
        vm.prank(developer);
        listing.setHookAddress(hook);

        // Set a no-op staking to prevent hook reverts on add liquidity
        FakeStaking fake = new FakeStaking();
        vm.prank(developer);
        SuperDCAGauge(address(hook)).setStaking(address(fake));
        key = super._initPoolWithHook(key, hook);
    }

    function test_CollectFeesNative_Reverts() public {
        // Mint and list
        uint256 nfpId = mintFullRange(key, 2_000e18, 2_000e18, address(this));
        IERC721(address(positionManagerV4)).approve(address(listing), nfpId);
        listing.list(nfpId, key);

        // Accrue fees via donation
        address token0Addr = Currency.unwrap(key.currency0);
        address token1Addr = Currency.unwrap(key.currency1);

        address recipient = address(0x1234);
        accrueFeesByDonation(key, 100e18, 100e18);

        // Assert Reverting
        vm.expectRevert();
        vm.prank(developer);
        listing.collectFees(nfpId, recipient);
    }

    // Create the same functions, just make them support Native token as token0
    function accrueFeesByDonation(PoolKey memory _key, uint256 amt0, uint256 amt1) internal {
        address t0 = Currency.unwrap(_key.currency0);
        address t1 = Currency.unwrap(_key.currency1);
        if(t0 == address(0)) {
            deal(address(this), amt0);
            deal(t1, address(this), amt1);
            IERC20(t1).approve(address(donateRouter), amt1);
            donateRouter.donate{value: amt0}(_key, amt0, amt1, "");
        } else {
            deal(t0, address(this), amt0);
            deal(t1, address(this), amt1);
            IERC20(t0).approve(address(donateRouter), amt0);
            IERC20(t1).approve(address(donateRouter), amt1);
            donateRouter.donate(_key, amt0, amt1, "");
        }
    }

    function mintFullRange(PoolKey memory _key, uint256 amount0, uint256 amount1, address owner)
    internal
    returns (uint256 nfpId)
    {
        fundAndApprove(owner, Currency.unwrap(_key.currency0), amount0);
        fundAndApprove(owner, Currency.unwrap(_key.currency1), amount1);

        int24 lower = TickMath.minUsableTick(_key.tickSpacing);
        int24 upper = TickMath.maxUsableTick(_key.tickSpacing);
        uint256 liquidity = _liquidityForAmounts(_key, amount0, amount1);

        Plan memory planner = Planner.init();
        planner = planner.add(
            Actions.MINT_POSITION,
            abi.encode(_key, lower, upper, liquidity, type(uint128).max, type(uint128).max, owner, bytes(""))
        );
        bytes memory calls = planner.finalizeModifyLiquidityWithClose(_key);

        nfpId = positionManagerV4.nextTokenId();
        vm.prank(owner);
        positionManagerV4.modifyLiquidities{value: amount1}(calls, block.timestamp + 60);
    }

    function fundAndApprove(address owner, address token, uint256 amt) internal {
        if (token == address(0)) {
            vm.deal(owner, amt);
        } else {
        deal(token, owner, amt);
        vm.prank(owner);
        IERC20(token).approve(address(permit2), type(uint256).max);
        vm.prank(owner);
        permit2.approve(token, address(posM), type(uint160).max, type(uint48).max);
        }
    }
}
```

### Mitigation
Add a native token (ETH, MATIC) check and use `recipient.balance` instead of `IERC20.balanceOf` when `Currency.unwrap(token) == address(0)`.
Consider creating internal function like this, for accounting correctly without, reverting:
```solidity
function _getBalance(Currency currency, address account) internal view returns (uint256) {
    address token = Currency.unwrap(currency);
    if (token == address(0)) {
        // native ETH / MATIC / BNB
        return account.balance;
    } else {
        return IERC20(token).balanceOf(account);
    }
}
```
Diff: 
```diff
-   uint256 balance0Before = IERC20(Currency.unwrap(token0)).balanceOf(recipient);
-   uint256 balance1Before = IERC20(Currency.unwrap(token1)).balanceOf(recipient);
+   uint256 balance0Before = _getBalance(token0, recipient);
+   uint256 balance1Before = _getBalance(token1, recipient);

// ... call modifyLiquidities ...

-   uint256 balance0After = IERC20(Currency.unwrap(token0)).balanceOf(recipient);
-   uint256 balance1After = IERC20(Currency.unwrap(token1)).balanceOf(recipient);
+   uint256 balance0After = _getBalance(token0, recipient);
+   uint256 balance1After = _getBalance(token1, recipient);
```

## Reward loss for stakers and developer when new stake/unstake occurs

## Severity
High

### Summary
`SuperDCAStaking::accrueReward()` returns `0` after stake/unstake because `info.lastRewardIndex` is overwritten on every stake/unstake. That causes all pending rewards for the token bucket to be lost. Since the gauge uses `accrueReward()` and then mints & splits the returned `rewardAmount` 50/50, both stakers and the developer team lose 100% of accumulated rewards whenever staking activity occurs. This is a critical economic failure and allows trivial griefing.

### Root Cause
- `rewardIndex` is a global index that grows over time.
- `tokenRewardInfo.lastRewardIndex` is set to rewardIndex inside stake() and unstake() after calling `_updateRewardIndex()`.
- Therefore, any rewards that accumulated before the stake/unstake call are never claimed; they are effectively discarded because [`accrueReward()`](https://github.com/sherlock-audit/2025-09-super-dca-PavelPindarev/blob/main/super-dca-gauge/src/SuperDCAStaking.sol#L276) computes `delta = rewardIndex - info.lastRewardIndex` and finds `delta == 0`.
- The gauge expects `accrueReward()` to return the full pending reward for that token bucket; instead, it returns 0 after an intervening stake/unstake, so `rewardAmount == 0` -> `developerShare == 0` and `communityShare == 0`.
- Attackers can exploit this by frontrunning or griefing with repeated minimal stake/unstake operations.

### Internal Pre-conditions
- Target token is already listed in protocol.
- There is at least one active staker with pending rewards.

### External Pre-conditions
- Attacker (or any user) is able to call `stake()`/`unstake()`with even a tiny amount.
- Gauge later calls `accrueReward()` expecting to mint rewards.

### Attack Path
1. User1 stakes a large amount into `tokenA`.  
2. Time passes → rewards accumulate (`previewPending(tokenA)` > 0).  
3. Attacker (or any new participant) calls `stake(tokenA, 1)` or `unstake()` with a small amount.  
4. `stake()`/`unstake()` runs `_updateRewardIndex()` and sets `info.lastRewardIndex = rewardIndex`.  
5. This overwrites pending rewards and resets the bucket state.  
6. When the gauge later calls `accrueReward(tokenA)`, `delta == 0`. Rewards minted = 0.
7. Both stakers and the developer permanently lose rewards.  
8. The attacker can repeat cheaply to grief the system indefinitely.  

### Impact
- **100% loss of pending rewards** for both stakers and the developer whenever a stake/unstake occurs before accrual.  
- Any attacker with a minimal stake can **wipe all accumulated rewards** for a pool.  
- Incentives collapse: users are disincentivized to stake, and developer revenue disappears.  
- Also, this can be achieved both as intended and unintended

### PoC
Place the following test contract into `super-dca-gauge/test/SuperDCAStaking.t.sol` file
```solidity
contract RewardDistribution is SuperDCAStakingTest {
    address user2;

    function setUp() public override {
        SuperDCAStakingTest.setUp();
        // can be normal user or attacker..
        user2 = makeAddr("User2");
        _mintAndApprove(user2, 1_000e18);
    }

    function test_reward_loss() public {
        uint256 depositAmount = 1_000e18;
        vm.prank(user);
        staking.stake(tokenA, depositAmount);
        uint256 start = staking.lastMinted();

        uint256 timePassedDelta = 2 weeks;
        vm.warp(start + timePassedDelta);

        uint256 accumulatedRewards = staking.previewPending(tokenA);
        assert(accumulatedRewards > 0);

        vm.prank(user2);
        staking.stake(tokenA, depositAmount);
        
        vm.prank(gauge);
        uint256 accuredRewards = staking.accrueReward(tokenA);
        assertEq(accuredRewards, 0);
    }

}
```

### Mitigation
Do not overwrite pending rewards on every stake/unstake. Instead:
- Accumulate them into a token-level pendingRewards field before mutating state.
- Update `accrueReward()` to return both the persisted pending and newly accrued delta.
- Reset pending to `0` only after rewards are claimed.

```diff
struct TokenRewardInfo {
    uint256 stakedAmount;
    uint256 lastRewardIndex;
+   uint256 pendingRewards;
}
```