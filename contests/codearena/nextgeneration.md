# Valid Findings:

### [M-2] Lack of deadline check in `Forwareder::ForwardRequest`

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

# Findings That Judges or Sponsors Invalidate:

### [H-1] Gasless transfers are not working correctly, gas fees are paid by the original token holder.

**Codearena link:** [Open](https://code4rena.com/audits/2025-01-next-generation/submissions/S-790)

**Impact:** Medium

**Likelihood:** High

## Description
The protocol is designed to enable gasless transactions, which improves user experience, especially for new users or those who do not have enough ETH to pay for gas. According to the [Docs](https://eips.ethereum.org/EIPS/eip-2771) for this feature, the process works as follows:

1. Transaction Signer: Signs & sends transactions to a Gas Relay
2. Gas Relay: Receives signed requests off-chain from Transaction Signers and pays gas to turn it into a valid transaction that goes through a Trusted Forwarder
3. Trusted Forwarder: A contract trusted by the Recipient to correctly verify signatures and nonces before forwarding the request from Transaction Signers
4. Recipient: A contract that accepts meta-transactions through a Trusted Forwarder

[![](image.png)](https://eips.ethereum.org/assets/eip-2771/example-flow.png)

Currently, the protocol gas fees are paid by the token holder, who also signs the transaction. This behaviour breaks one of the key features of the protocol. The issue can be found to the `EURFToken::transfer` and `EURFToken::transferWithAuthorization` functions.

## Impact
One of the key features of the protocol is not functioning properly. Token holders are required to pay all gas fees, which can be unpredictable and it is making gasless transfers imposible. As a result, some transfers may fail to occur if the token holders do not have enough balance in their accounts to cover these fees.

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
4. In the `ERC20MetaTxUpgradeable` smart contract place the following code for successfully reproducing the tests:

```solidity
    function getPermitMessageHash(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_PERMIT_TYPEHASH, owner, spender, value, nonce, deadline)));
    }

    function getTWAMessageHash(
        address holder,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_TWA_TYPEHASH, holder, spender, value, nonce, deadline)));
    }
```

5. In the test folder, create a test file named `EURFTokenTest.t.sol` for example, and place the following code into: 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {EURFToken} from "contracts/Token.sol";
import {Forwarder} from "contracts/Forwarder.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract EURFTokenTest is Test {
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

    modifier gaslessSetup() {
        vm.prank(owner);
        token.setAdministrator(admin);
        vm.prank(owner);
        token.setMasterMinter(masterMinter);
        vm.prank(masterMinter);
        token.mint(bob, 10000);
        vm.prank(masterMinter);
        token.mint(alice, 10000);

        Forwarder fwdImpl = new Forwarder();
        bytes memory data = abi.encodeWithSelector(fwdImpl.initialize.selector, address(token));
        vm.prank(owner);
        ERC1967Proxy proxyForward = new ERC1967Proxy(address(fwdImpl), data);
        forwarder = Forwarder(payable(proxyForward));

        vm.startPrank(admin);
        token.setTrustedForwarder(address(forwarder));
        token.setFeeFaucet(owner);
        token.setTxFeeRate(1000);
        token.setGaslessBasefee(1000);
        vm.stopPrank();
        _;
    }

    function testGaslessTransfer() public gaslessSetup {
        vm.prank(masterMinter);
        token.mint(address(forwarder), 10000);

        uint256 amountToTransfer = 2000;
        uint256 startingBalanceOfBob = token.balanceOf(bob); // 10000
        uint256 startingBalanceOfAlice = token.balanceOf(alice); // 10000
        // 1. Alice Signs off-chain (vm.sign) custom ERC20 token function (spender should be Forwader contract)
        // `permit(owner, spender, value, deadline, v, r, s)`
        // So here Alice's signing allows Forwarder Contract to used to execute the transaction instead of her and she will not pay any gas
        uint256 deadline = block.timestamp + 1 days;

        bytes32 digest = token.getPermitMessageHash(alice, address(forwarder), amountToTransfer, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        // 2. Paymaster (maybe forwardOperator) invokes ERC-20 `permit` function and broadcasts the previously signed payload on-chain
        vm.prank(forwardOperator);
        token.permit(alice, address(forwarder), amountToTransfer, deadline, v, r, s);
        assertEq(token.allowance(alice, address(forwarder)), amountToTransfer);

        // 3. Alice Signs the ForwardRequest payload off-chain, containing the calldata for the standard ERC-20 token function
        // `transferFrom(sender, recipient, amount)` (recipient maybe Bob)
        // transferFrom(Alice, Bob, 2000)
        bytes memory callData = abi.encodeWithSelector(token.transfer.selector, bob, amountToTransfer);
        (
            Forwarder.ForwardRequest memory request,
            bytes32 domainSeparator,
            bytes32 typeHash,
            bytes memory suffixData,
            bytes memory signature
        ) = _buildForwarderMessage(alice, address(token), 1e12, 0, callData);

        // 4. Paymaster (maybe forwardOperator) invokes the `execute` function in the Forwarder contract with previously signed payload, thus broadcasting the `transfer` transaction
        vm.prank(forwardOperator);
        forwarder.execute(request, domainSeparator, typeHash, suffixData, signature);

        uint256 transferFee = token.calculateTxFee(amountToTransfer);
        uint256 totalFees = token.getGaslessBasefee() + transferFee;

        // 5. Assert that tokens are transfered to Bob
        assertEq(token.balanceOf(bob), startingBalanceOfBob + amountToTransfer);
        // 6. Assert that Alice has payed all of the gass!
        assertEq(token.balanceOf(alice), startingBalanceOfAlice - amountToTransfer - totalFees);
    }

    function testTransferWithAuthorization() public gaslessSetup {
        uint256 amountToTransfer = 2000;
        uint256 startingBalanceOfBob = token.balanceOf(bob); // 10000
        uint256 startingBalanceOfAlice = token.balanceOf(alice); // 10000
        uint256 deadline = block.timestamp + 1 days;

        // 1. Alice signs off-chain to transfer bob 2000 tokens
        bytes32 digest = token.getTWAMessageHash(alice, bob, amountToTransfer, 0, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        uint256 transferFee = token.calculateTxFee(amountToTransfer);

        // 2. Bob calls the transfer and he is spender so he should pay the gas fees
        vm.prank(bob);
        token.transferWithAuthorization(alice, bob, amountToTransfer, deadline, v, r, s);

        // 3. Assert that Alice has paid the gas
        assertEq(token.balanceOf(alice), startingBalanceOfAlice - amountToTransfer - transferFee);
        assertEq(token.balanceOf(bob), startingBalanceOfBob + amountToTransfer);
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
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
6. Run the following command in the terminal `forge test --via-ir`

</details>

## Recommended mitigation
So if there is still some fee gathering for gasless transfers for token holders, at least change the way `transferSanity` functions calls `_payTxFee`.
Consider adding an additional function parameter to `transferSanity` which is responsible for paying fees.

Example:
```diff
    function transferSanity(
        address sender,
+       address payer,
        address recipient,
        uint256 amount) internal {
        adminSanity(sender, recipient);
-       if (_txfeeRate > 0) _payTxFee(sender, amount);
+       if (_txfeeRate > 0) _payTxFee(payer, amount);
    }

    function transfer(address recipient, uint256 amount) public override returns (bool) {
        transferSanity(_msgSender(),
+           msg.sender,
            recipient,
            amount
        );
        return super.transfer(recipient, amount);
    }

    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        transferSanity(sender,
+           sender,
            recipient,
            amount
        );
        return super.transferFrom(sender, recipient, amount);
    }

    function transferWithAuthorization(
        address holder,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public override returns (bool) {
        transferSanity(holder,
+           spender/msg.sender,
            spender,
            value
        );
        return super.transferWithAuthorization(holder, spender, value, deadline, v, r, s);
    }

```



### [M-1] Wrong calculation of fees in `FeesHandlerUpgradeable::calculateTxFee`. Transactions can be executed without paying any gas.

**Codearena link:** [Open](https://code4rena.com/audits/2025-01-next-generation/submissions/S-792)

**Impact:** Medium

**Likelihood:** Medium

## Description 
Function `calculateTxFee` is used to calculate the transaction fee based on amount of tokens that are being transfered multiplied by transaction fee rate setted by the admin and value fo that is divided by `FEE_RATIO` in this case 10000. However, the user can take advantage of rounding down in the EVM to avoid paying any fees.

```solidity
   function calculateTxFee(uint256 txAmount) public view returns (uint256) {
        return (txAmount * _txfeeRate) / FEE_RATIO;
    }
``` 

## Impact
Users can avoid paying fees to the protocol due to rounding.

## Proof of Concepts
 To exploit this, the user can transfer tokens in very small batches. For instance, if a user wants to withdraw 1,000,000 tokens, they can repeatedly request a withdrawal of just 49 tokens. This specific amount is chosen because, with a nominal fee rate of 2%, the calculated fee should round down to zero:    

```solidity
    49 * 200 / 10000 = 0
```

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

    function testTxFeeRate() public setupForForwarderTests {
        vm.startPrank(admin);
        token.setFeeFaucet(feesFaucet);
        token.setTxFeeRate(200); // 2% -> FEE_RATIO x 2% -> 10000 × 0,02 = 200
        vm.stopPrank();

        vm.prank(bob);
        token.transfer(alice, 49);

        // No one has paid gas!
        assertEq(token.balanceOf(feesFaucet), 0);
        assertEq(token.balanceOf(bob), 1000 - 49);
        assertEq(token.balanceOf(alice), 1000 + 49);
    }
}
```
5. Run the following command in the terminal `forge test --mt testTxFeeRate`
6. 
</details>

## Recommended mitigation
Two solutions are suggested:

1. Modify the fee calculation in `calculateTxFee` to always round up, ensuring that no withdrawal is completely free of charge.
2. Set a minimum fee threshold so that no calculated fee results in zero, irrespective of the transaction amount.

Examples:

1. 
```diff
    function calculateTxFee(uint256 txAmount) public view returns (uint256) {
-       return (txAmount * _txfeeRate) / FEE_RATIO;
+       return (txAmount * _txfeeRate + FEE_RATIO - 1) / FEE_RATIO;
    }
```

2.
```diff
+   uint256 public constant MIN_FEE = 1; // or whatever minimum makes sense

    function calculateTxFee(uint256 txAmount) public view returns (uint256) {
+       uint256 fee = (txAmount * _txfeeRate) / FEE_RATIO;
+       if (txAmount > 0 && fee == 0) {
+           return MIN_FEE;
+       }
+       return fee;
-       return (txAmount * _txfeeRate) / FEE_RATIO;
    }
```

