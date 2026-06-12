## Stakers using `deposit()` + `delegate()` silently have zero veto power

### Description

The contract maintains **two independent** delegation systems:

1. **Standard ERC20Votes** — used by the standard `propose`/`castVote` path. Activated by `delegate()` and updated automatically inside `_update` (transfers).
2. **Optimistic veto** — `optimisticDelegateCheckpoints`, accessed by the optimistic veto path via `getPastOptimisticVotes`. Only activated by `delegateOptimistic()` or `depositAndDelegate(assets, delegatee, optimisticDelegatee)`.

Token transfers move only the **standard** votes via `_update`; optimistic checkpoints are touched only when the user explicitly opts in:

```solidity
// contracts/staking/StakingVault.sol:546-553
function _delegateOptimistic(address account, address delegatee) internal {
    address oldDelegate = optimisticDelegatees[account];
    optimisticDelegatees[account] = delegatee;
    emit OptimisticDelegateChanged(account, oldDelegate, delegatee);
    _moveOptimisticDelegateVotes(oldDelegate, delegatee, balanceOf(account));
}
```

A user who deposits via plain `deposit(assets, receiver)` and then calls `delegate(self)` has full ERC20Votes power but zero optimistic veto power. Token recipients via `transfer` are in the same state — `_update` calls `_moveOptimisticDelegateVotes(optimisticDelegatees[from], optimisticDelegatees[to], value)` ([`StakingVault.sol:508`](../contracts/staking/StakingVault.sol#L508)), and if `to` has no optimistic delegate set, the votes route to `address(0)` and are not credited anywhere.

The optimistic governance safety net (token holders veto malicious optimistic proposals within a short window) is therefore weakened in proportion to how many users skip `depositAndDelegate(...,...,...)` or `delegateOptimistic()`.

### Proof of Concept

PoC lives at [`test/AuditPoC.t.sol`](../test/AuditPoC.t.sol) inside the existing `AuditPoC_NoOptimisticDelegate` contract and runs with:

```bash
forge test --match-contract AuditPoC_NoOptimisticDelegate -vv
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { StakingVault } from "@src/staking/StakingVault.sol";
import { UnstakingManager } from "@src/staking/UnstakingManager.sol";
import { ReserveOptimisticGovernanceVersionRegistry } from "@src/VersionRegistry.sol";
import { RewardTokenRegistry } from "@staking/RewardTokenRegistry.sol";
import { ThrottleLib } from "@governance/lib/ThrottleLib.sol";

import { MockERC20 } from "@mocks/MockERC20.sol";
import { MockRoleRegistry } from "@mocks/MockRoleRegistry.sol";

/// @title Shared base — bypasses the project's broken Deployer by impersonating its
/// interface (`rewardTokenRegistry()` + `versionRegistry()`) so the test contract is
/// `msg.sender` to `StakingVault.initialize`.
abstract contract AuditPoCBase is Test {
    MockRoleRegistry internal roleRegistry;
    ReserveOptimisticGovernanceVersionRegistry internal _versionRegistry;
    RewardTokenRegistry internal _rewardTokenRegistry;

    address internal constant ALICE = address(0x123123001);
    address internal constant BOB = address(0x123123002);
    address internal constant CAROL = address(0x123123003);
    address internal constant ATTACKER = address(0xBADBAD);

    // ---- Deployer interface (consumed by StakingVault.initialize) ----
    function rewardTokenRegistry() external view returns (address) {
        return address(_rewardTokenRegistry);
    }

    function versionRegistry() external view returns (address) {
        return address(_versionRegistry);
    }

    function _setupRegistries() internal {
        roleRegistry = new MockRoleRegistry(address(this));
        _versionRegistry = new ReserveOptimisticGovernanceVersionRegistry(roleRegistry);
        _rewardTokenRegistry = new RewardTokenRegistry(roleRegistry);
    }

    function _deployVault(IERC20 underlying, uint256 halfLife, uint256 unstakingDelay)
        internal
        returns (StakingVault vault)
    {
        address vaultImpl = address(new StakingVault());
        bytes memory initData = abi.encodeCall(
            StakingVault.initialize,
            ("Vote-Locked", "vl", underlying, address(this), halfLife, unstakingDelay)
        );
        vault = StakingVault(address(new ERC1967Proxy(vaultImpl, initData)));
    }
}

contract AuditPoC_NoOptimisticDelegate is AuditPoCBase {
    MockERC20 token;
    StakingVault vault;

    function setUp() public {
        _setupRegistries();
        token = new MockERC20("Test", "TEST");
        vault = _deployVault(IERC20(address(token)), 3 days, 1 weeks);

        token.mint(ALICE, 100e18);
        vm.startPrank(ALICE);
        token.approve(address(vault), 100e18);
        // Plain deposit + standard delegate (NOT depositAndDelegate, NOT delegateOptimistic).
        vault.deposit(100e18, ALICE);
        vault.delegate(ALICE);
        vm.stopPrank();
    }

    function test_plainStaker_hasZeroOptimisticVotes() public {
        // Standard ERC20Votes power: 100e18.
        assertEq(vault.getVotes(ALICE), 100e18);

        // Optimistic veto power: 0 — a separate delegation system.
        assertEq(vault.getOptimisticVotes(ALICE), 0);

        // Past lookups (used by the governor at proposal snapshot) also return 0.
        vm.roll(block.number + 1);
        vm.warp(block.timestamp + 1);
        assertEq(vault.getPastOptimisticVotes(ALICE, block.timestamp - 1), 0);
    }
}
```

### Recommended Mitigation

Pick one of:

1. **Auto-mirror standard delegation in `_delegate`**: when `_delegate(account, x)` runs, if `optimisticDelegatees[account] == address(0)`, also call `_delegateOptimistic(account, x)`. Preserves user intent without a separate API.
2. **Auto-self-delegate optimistic on first transfer-in** in `_update`: if `optimisticDelegatees[to] == address(0)`, default it to `to`.

If the dual-delegation distinction is intentional, rename `delegate` to make the two systems unambiguous and require explicit opt-in to one of them at deposit time (revert any path that doesn't traverse `depositAndDelegate(...,...,...)`).