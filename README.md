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

It contains two functions namely `serialize_transaction` and `serialize_transaction_witness`. As the name suggests, first function is used to serialise non-segwit transactions while the second function is used to serialise segwit transactions.

I chose to implement these functions because they build the cornerstone for almost everything ahead, including making the message hash for verification, making txids, wtxids, etc.

Once my serialisation process was completed, I went on to verify p2pkh transactions first.

### `p2pkh.py`
