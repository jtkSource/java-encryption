# java-encryption
Libraries for Standard encryption

## AES Algorithm
The AES algorithm is an iterative, symmetric-key block cipher that supports cryptographic keys (secret keys) of 128, 192, 
and 256 bits to encrypt and decrypt data in blocks of 128 bits. 
The below figure shows the high-level AES algorithm:

![https://www.baeldung.com/java-aes-encryption-decryption](https://www.baeldung.com/wp-content/uploads/2020/11/Figures.png "Symmetric-key cipher")

> If the data to be encrypted doesn't meet the block size requirement of 128 bits, it must be padded. 
> Padding is the process of filling up the last block to 128 bits.

Following variations of AES algorithm are available:

- ECB
- CBC
  - In CBC mode, you encrypt a block of data by taking the current plaintext block and XOR’ing with the previous 
  ciphertext block and which cannot be written in parallel, this significantly affects the 
  performance of AES-CBC encryption and AES-CBC also is vulnerable to padding oracle attacks
- CFB
- OFB
- CTR
- GCM 
  - AES-GCM is a block cipher mode of operation that provides high speed of authenticated encryption and data integrity. 
  In GCM mode, the block encryption is transformed into stream encryption, and therefore no padding is needed
  GCM mode maintains a counter for each block of data and sends the current value of the counter to the block cipher 
  and the output of the block cipher is XOR’ed with the plain text to get the ciphertext. 
  The counter mode of operation is designed to turn block ciphers into stream ciphers. 
  > AES GCM is written in parallel and each block with AES GCM can be encrypted independently, 
  hence the performance is significantly higher than AES CBC.
 
  
