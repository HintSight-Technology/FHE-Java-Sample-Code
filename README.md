# FHE Java Sample Code 

This sample code demonstrates the use of Encryption and Decryption of a feature vector, in Java.

### Encryption
The encrypt function takes in two inputs: feature vectors and public key. It outputs an encrypted feature vector. 
```
long[][] encryptedFeatures1 = Encryption.encrypt(features1, publicKey);
```

### Decryption 
The decryption function takes as input: polynomial degree, ciphertext modulus, plaintext modulus, secret key and the encrypted feature vector. 
It outputs the decrypted feature vector result. 
```
long[] decryptedResult1 = Decryption.rlwe64Dec(polyDegree, ciphertextModulus, plaintextModulus,
                secretKey, encryptedFeatures1);
```
