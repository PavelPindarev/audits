# Valid Findings:

### Lack of deadline check in `Forwareder::ForwardRequest`

**Codearena link:** [Open](https://code4rena.com/audits/2025-01-next-generation/submissions/S-793)

**Impact:** Medium

**Likelihood:** Medium

## Description
Without a deadline parameter, each ForwardRequest is potentially valid indefinitely. This means that once a request is signed, it can be executed at any point in the future, provided that the nonce has not yet been used. If a request remains valid forever without a deadline, allowing it to be executed much later than the signer might have intended. This can lead to situations where the execution context (e.g., market conditions, contract states) has drastically changed from when the request was originally signed. Signers have no mechanism to limit the time window during which their request is valid, reducing their control over their own transactions.


Originally if we see the docs about ERC-2770 that is used here, we can see what ForwardRequest looks like and what fields MUST have at least. https://eips.ethereum.org/EIPS/eip-2770

<em>Request struct MUST contain the following fields in this exact order:</em>
```solidity
struct ForwardRequest {
   address from;
   address to;
   uint256 value;
   uint256 gas;
   uint256 nonce;
   bytes data;
   uint256 validUntil;
}
```

## Impact 
Omitting the `validUntil` field means that each signed meta‑transaction never expires, leaving it valid indefinitely. This indefinite validity can lead to replay attacks or unwanted future execution—even if market conditions or a user's intentions have changed.

## Proof of Concepts

<details>
<summary>PoC</summary>

**Setup** 
1. If you don't have Foundry installed -> https://book.getfoundry.sh/getting-started/installation
2. We need to install all needed dependencies by running `forge install foundry-rs/forge-std openZeppelin/openzeppelin-contracts openZeppelin/openzeppelin-contracts-upgradeable --no-commit` in the terminal
3. Create foundry.toml file in the root folder and place the following code into:

```toml
[profile.default]
src = "contracts"
out = "out"
libs = ["lib"]
remappings = [
    "@openzeppelin/contracts=lib/openzeppelin-contracts/contracts",
    "@openzeppelin/contracts-upgradeable=lib/openzeppelin-contracts-upgradeable/contracts",
]
```
4. In the test folder, create a test file named `EURFTokenTest.t.sol` for example, and place the following code into: 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {EURFToken} from "contracts/Token.sol";
import {Forwarder} from "contracts/Forwarder.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract EURFTokenTest is Test {

    uint256 constant FEE_RATIO = 10000;

    address owner = vm.addr(1);
    address admin = vm.addr(3);
    address masterMinter = vm.addr(5);
    address minter = vm.addr(7);
    address feesFaucet = vm.addr(10);
    address bob;
    uint256 bobKey;
    address alice;
    uint256 aliceKey;
    address forwardOperator = vm.addr(14);

    EURFToken public token;
    Forwarder public forwarder;

    EURFToken public tokenImpl;

    function setUp() public {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
        tokenImpl = new EURFToken();

        bytes memory data = abi.encodeWithSelector(tokenImpl.initialize.selector);

        vm.startPrank(owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(tokenImpl), data);
        token = EURFToken(address(proxy));

        token.setAdministrator(admin);
        vm.stopPrank();
    }

    modifier setupForForwarderTests() {
        vm.prank(owner);
        token.setAdministrator(admin);
        vm.prank(owner);
        token.setMasterMinter(masterMinter);
        vm.prank(masterMinter);
        token.mint(bob, 1000);
        vm.prank(masterMinter);
        token.mint(alice, 1000);

        Forwarder fwdImpl = new Forwarder();
        bytes memory data = abi.encodeWithSelector(fwdImpl.initialize.selector, address(token));
        vm.prank(owner);
        ERC1967Proxy proxyForward = new ERC1967Proxy(address(fwdImpl), data);
        forwarder = Forwarder(payable(proxyForward));
        _;
    }

    function testExecuteForwardRequestAfterAYear() public setupForForwarderTests {
        vm.prank(admin);
        token.setTrustedForwarder(address(forwarder));

        // Build the call data for transfer(alice, 50)
        bytes memory callData = abi.encodeWithSelector(token.transfer.selector, alice, 50);

        // Bob Signing
        (
            Forwarder.ForwardRequest memory request,
            bytes32 domainSeparator,
            bytes32 typeHash,
            bytes memory suffixData,
            bytes memory signature
        ) = _buildForwarderMessage(bob, address(token), 1e12, 0, callData);

        // Set the block timestamp year from now, and increase block.number
        vm.warp(block.timestamp + 365 days);
        vm.roll(100);

        // Execute
        vm.prank(forwardOperator);
        forwarder.verify(request, domainSeparator, typeHash, suffixData, signature);
        forwarder.execute(request, domainSeparator, typeHash, suffixData, signature);

        // Check balances
        assertEq(token.balanceOf(bob), 950);
        assertEq(token.balanceOf(alice), 1050);
    }

    function _buildForwarderMessage(address from, address to, uint256 gas, uint256 nonce, bytes memory data)
        internal
        view
        returns (
            Forwarder.ForwardRequest memory request,
            bytes32 domainSeparator,
            bytes32 typeHash,
            bytes memory suffixData,
            bytes memory signature
        )
    {
        request = Forwarder.ForwardRequest({from: from, to: to, value: 0, gas: gas, nonce: nonce, data: data});

        domainSeparator = keccak256(abi.encodePacked("Forwarder", address(token)));
        typeHash =
            keccak256("ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data)");
        suffixData = abi.encode(block.timestamp + 1 days);

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, keccak256(getEncoded(request, typeHash, suffixData)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function getEncoded(Forwarder.ForwardRequest memory req, bytes32 requestTypeHash, bytes memory suffixData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            requestTypeHash,
            abi.encode(req.from, req.to, req.value, req.gas, req.nonce, keccak256(req.data)),
            suffixData
        );
    }
}
```

5. Run the following command in the terminal `forge test --mt testExecuteForwardRequestAfterAYear`
   
</details>

## Recommended mitigation
Adjust the `ForwardRequest` struct to include a deadline parameter. Consider implementing logic within the contract's execution function to check the current block timestamp against the request's deadline, rejecting any requests that are past their expiration.

Example:

```diff
contract Forwarder is OwnableUpgradeable {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
+       uint256 validUntil;
    }
.
.    
+   error Forwarder__ForwardRequestExpired();

    string public constant GENERIC_PARAMS = "address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data,
+   uint256 validUntil";
.
.
.
    function execute(
        ForwardRequest calldata req,
        bytes32 domainSeparator,
        bytes32 requestTypeHash,
        bytes calldata suffixData,
        bytes calldata sig
    ) external payable returns (bool success, bytes memory ret) {
        _verifyNonce(req);
        _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
        _updateNonce(req);

+       if(block.timestamp > req.validUntil) {
+           revert Forwarder__ForwardRequestExpired();
+       }

        require(req.to == _eurfAddress, "NGEUR Forwarder: can only forward NGEUR transactions");

        bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
        bytes4 reqTransferSelector = bytes4(req.data[:4]);

        require(reqTransferSelector == transferSelector, "NGEUR Forwarder: can only forward transfer transactions");

        (success, ret) = req.to.call{gas: req.gas, value: req.value}(abi.encodePacked(req.data, req.from));
        require(success, "NGEUR Forwarder: failed tx execution");


        _eurf.payGaslessBasefee(req.from, _msgSender());

        return (success, ret);
    }

}
```
This solution can be used in `Forwarder::verify` function also. 