# Bouncy-Castle-PGP-GPG-ByteArray

### Purpose
This is a utility library provides commonly used bouncy castle functions.

Currently this library provides following functions:
* BCPGPEncryptor, BCPGPDecryptor, RSAKeyPairGenerator : encrypt, decrypt, sign and verify GPG/PGP/OpenPGP data with just a few lines of code using Bouncy Castle's OpenPGP utility.


### Usage
Include the following dependency in the pom file.
```
<dependency>
	<groupId>com.thunder.indika.utils</groupId>
	<artifactId>utils-bouncy-castle</artifactId>
	<version>1.0.0-SNAPSHOT</version>
</dependency>

```

### Code snippet to encrypt and sign
```
byte[] encryptedBytes = BCPGPEncryptor.getInstance().encryptAndSign(clearPayload.getBytes(), receiverPublicKey.getBytes(), isSigned, senderPrivateKey.getBytes(), senderPassword, isArmored);
```

### Code snippet to decrypt and verify signature
```
byte[] decryptedBytes = BCPGPDecryptor.getInstance().decryptAndVerifySignature(encryptedPayload.getBytes(), receiverPrivateKey.getBytes(), receiverPassword, isSigned, senderPublicKey.getBytes());
```
### Note
If you get error "java.security.InvalidKeyException: Illegal key size", you may need to install
the unrestricted policy files for the JVM you are using.