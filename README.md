# Summer of Bitcoin 2024

## Synopsis

Our assignment was to mine a block without using any external libraries. In the coming sections I will be sharing my approach on how I tackled the problem statement. I have used **NO "external" libraries**. I have only used libraries such as `hashlib` (for hashing functions), `os` and `json`. I implemented all elliptical calculations myself.

## Script

```
python .\main.py

```

## Code

So I will explain the code in the flow I coded it, and solved the problem, starting with `serialise.py`.

### `serialise.py`

It contains two functions namely `serialize_transaction` and `serialize_transaction_witness`. As the name suggests, first function is used to serialise non-segwit and segwit transactions both for txid calculations while the second function is used to serialise segwit transactions for wtxid calculation.

I chose to implement these functions because they build the cornerstone for almost everything ahead, including making the message hash for verification, making txids, wtxids, etc.

Once my serialisation process was completed, I went on to verify p2pkh transactions first. But before that, I would like to explain `verify.py` where I implemented `opchecksig` from scratch, making all elliptical calculations as well.

### `verify.py`

Verification at its core is if
`(s⁻¹ * z)G + (s⁻¹ * r)Q `is equal to R or not.
Here, R and S are components of DER signature, Q is the public key, z is the message hash and G is the generator point.

I implemented `opchecksig` for verification of signatures which used `add`, `multiply`, `double` and `inverse` functions, all defined in the same file.

Once I was done testing verify.py, I went to implement p2pkh transactions

### `p2pkh.py`

The main function `verify_signature` takes a JSON object as input and returns True or False. If all the signatures are valid for all the inputs, True is returned.

The file has many more functions defined as well. One important step in verifying p2pkh transactions was to remove exisiting script sigs from the JSON data. In order to optimise, I made a copy of JSON data with signatures intact, while defined a function `clear_scriptsig` which cleared all the signatures for all inputs. Then I iterated all inputs, put the relevant pubkey script in the sigscript for the input we are currently in, serialised the message, and then verified the signature.

To verify the signature, a particular format for pubkey and signature need to be used for input in opchecksig. So I defined two more functions `dissect_signature` (Takes a DER signature and returns R and S component of it) and `decompress_pubkey` (Takes a x_only pubkey and returns me public key in (x,y) format)

Process of verifying p2wpkh transaction was also very similar. I defined all functions in `p2wpkh.py` in a very similar manner. Only difference was the way witness was handled. Because the approach is very similar, I am skipping it in the ReadME.

### `merkle_root.py`

This was necessary for calculating merkle root for header.
I defined two function in here, mainly `calculate_txid_array` which returns me an array consisting of all the txids in natural byte ordering, and another function `calc_merkle_root` which calculates merkle root. Merkle root is nothing but taking hash of 2 consecutive txids, repetitively until only one hash remains. I used a temp array to store the hash in each iteration, and at the end, I used to replace my original txid array with temp array, and make temp array empty again.

Similar to this I also have defined `witness_commitment.py` which has very similar implementation. Only difference being that `calc_merkle_root` needs txid for coinbase as a parameter, `calc_witness_commitment` takes wtxid of coinbase as 0. Also, the here instead of txid array, we use wtxid array (We have already defined a function in our `serialise.py` to calculate wtxid).

Because of a very similar implementation, I choose not to devote a seperate section for `witness_commitment.py` in this doc.

### `header.py`

This file is very similar. It contains two functions:
`make_header()` which adds all the things such as time, merkle root, etc to the header. The second function `make_hash()` is responsible for finding a nonce such that hash of header is less than difficulty target.

### `main.py`

This is the final file which runs all the functions and makes the output.txt. My workflow is: I run `verify_transactions()` and write all the verified p2pkh and p2wpkh transactions in valid_transactions.txt (In order to keep my block under weight limit, I have broken the loop at a point when enough transations were included already). Then `make_block()` is called which calls `make_coinbase()` to make the coinbase, and then calls `make_hash()` to make a header with valid nonce, and then finally calls `calculate_txid()` to included txids of the valid_transactions in the block.

With this, my block is mined, and I got a score of 93. With my endsemester exams going on, and proposal left, I did not try to optimise the score/time of the code. But I had few optimisations in mind. Most basic one was to sort all the verified transactions based on their fee and then start taking the transactions with most fees. I could have also optimised run time at places by changing the implementation or maybe some data structures, but due to lack of time I couldn't.

## Tirth Bhayani

## IIT-BHU
