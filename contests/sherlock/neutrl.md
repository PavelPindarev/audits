# Valid Findings:

## Role Consistency Invariant is Broken - FULL_RESTRICTED Users Can Transfer via Deposit/Mint

### Summary
So in the protocol, we have this as details and an invariant.
```
What properties/invariants do you want to hold even if breaking them has a low/unknown impact?
.
.
.
7.Role Consistency
Property: FULL_RESTRICTED users cannot transfer and stake/unstake, SOFT_RESTRICTED cannot stake
Description: Blacklist roles must be properly enforced across all operations
Location: sNUSD.sol and NUSD.sol
```
A missing access control check in the `sNUSD::_deposit` function will cause a complete breakdown of the blacklisting system for stakers as `FULL_RESTRICTED` users will be able to transfer value to unrestricted accounts through deposit operations.

### Root Cause
The idea is that when a user is blacklisted as `FULL_RESTRICTED_STAKER_ROLE`, they are unable to make any transfers at all, so their funds (`NUSD`) are effectively locked or frozen.
In the `sNUSD` contract, there is a mechanism that will eventually unlock these funds by either sending them to a non-restricted user or adding them to the vesting amount.
```solidity
    function redistributeLockedAmount(address from, address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            if (amountToDistribute == 0) revert ZeroInput();
            uint256 nusdToVest = previewRedeem(amountToDistribute);
            _burn(from, amountToDistribute);
            // to address of address(0) enables burning
            if (to == address(0)) {
                _updateVestingAmount(nusdToVest);
            } else {
                _mint(to, amountToDistribute);
            }
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```
However, a blacklisted user as the `FULL_RESTRICTED_STAKER_ROLE` is able to make transfers like depositing and minting to a non-restricted user, so his `NUSD` won't be locked. 
The blacklisted user can use another account and transfer the `locked` or `frozen` funds to it.

Why is this happening?

This occurs because, during each ERC4626 `deposit` or `mint`, the `_deposit` function is called, which in turn invokes ERC20's `_mint` method. By default, the `_update` function is then called with `address(0)` as the first parameter.
```solidity
   function _mint(address account, uint256 value) internal {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _update(address(0), account, value);
    }

```
This causes our override of the `_update` function to be ineffective.
The first check is for filtering any restricted addresses, but in our case, this will never hit, due to `ERC20::_mint`, where from parameter is always passed as `address(0)`.
```solidity
    function _update(address from, address to, uint256 value) internal override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
        super._update(from, to, value);
    }
``` 

### Internal Pre-conditions
Admin needs to assign `FULL_RESTRICTED_STAKER_ROLE` to a malicious user address.
The malicious user needs to have `NUSD` tokens to deposit.
The cooldown mechanism must not be paused.

### External Pre-conditions
The malicious user needs to have access to at least one non-restricted address (another account they control).

### Attack Path
1. Admin with the role `DEFAULT_ADMIN_ROLE` detects malicious activity and blacklists a user by granting them `FULL_RESTRICTED_STAKER_ROLE`
2. The blacklisted user calls `deposit()` or `mint()` functions with their restricted address as the caller and their non-restricted address as the receiver
3. The deposit succeeds because the _deposit function doesn't check if the caller has FULL_RESTRICTED_STAKER_ROLE
4. The restricted user's `NUSD` is converted to sNUSD shares and transferred to the non-restricted address
5. The non-restricted account can now freely unstake or transfer the shares

### Impact
The protocol suffers a complete breakdown of its blacklisting mechanism. `FULL_RESTRICTED` users can bypass the transfer restrictions, making the `redistributeLockedAmount` function useless. Malicious actors can continue their activities despite being blacklisted, potentially causing significant financial harm to the protocol.

### PoC
In `contracts/test/unit/concrete/sNUSD/restricted/sNUSD_restricted.t.sol` place this test, which proves that a user with role `FULL_RESTRICTED_STAKER_ROLE` can transfer `NUSD` to other user or account.

```solidity
    function test_StakingRestrictionsWhenAddressHas_FULL_RESTRICTED_STAKER_ROLE_to_Not_Restricted() external {
        // Get the asset (NUSD) for the user to deposit
        deal(address(nusd), fullRestrictedUser, testAmount);

        vm.startPrank(fullRestrictedUser);
        nusd.approve(address(sNusd), testAmount);

        // Deposit should revert for FULL_RESTRICTED_STAKER_ROLE, but it's not
        uint256 sharesBefore = sNusd.balanceOf(normalUser);
        sNusd.deposit(testAmount, normalUser);
        uint256 sharesAfter = sNusd.balanceOf(normalUser);
        vm.stopPrank();

        assertTrue(sharesAfter > sharesBefore, "Shares balance should increase after deposit");
    }
```

### Mitigation
Consider adding Authorizing checks on `sNUSD::_deposit` function, so for every new `sNUSD::deposit` or `sNUSD::mint` calls, there is checking for that.
Adding a check at least for `caller` will help, because `receiver` is later checked in `_update`.

```diff
   function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
       
+       if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
-       if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
            revert OperationNotAllowed();
        }
        if (assets == 0 || shares == 0) revert ZeroInput();
        super._deposit(caller, receiver, assets, shares);
        _checkMinShares();
    }

```