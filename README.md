#An Attack on Offset Public Permutation Mode

Offset Public Permutation Mode ([OPP](https://eprint.iacr.org/2015/999.pdf)) by Granger et al. is a one-pass authenticated encryption scheme supporting associated data (AEAD scheme). 
Leveraging an error in analysis of the scheme, a chosen plaintext attack that creates a forgery was discovered. 
This attack makes no assumptions about the underlying tweakable blockcipher while having negligible complexity requirements and high probability of success. 
This is a proof-of-concept implementation of the attack.

In this version, we generate a valid ciphertext by shortening another valid ciphertext with a special plaintext (with a one-byte long last block).
Then we find the valid last block by checking all 256 possibilities.

The attack can be found implemented in the `attack.c` file.
The `ref` folder contains the scheme implementation provided by the authors of [OPP](https://github.com/MEM-AEAD/mem-aead).

To try the attack, just hit `make`.

The full article can be found on [e-print](https://eprint.iacr.org/2018/351.pdf).
