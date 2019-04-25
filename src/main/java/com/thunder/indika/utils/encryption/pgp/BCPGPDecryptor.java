package com.thunder.indika.utils.encryption.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

/**
 * Provides decrypt and verify signature method using bouncy castle library.
 * supports Open PGP, GPG cryptographic systems.
 */
public class BCPGPDecryptor {

	private static BCPGPDecryptor INSTANCE = null;

	private BCPGPDecryptor() {
	}

	public static BCPGPDecryptor getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new BCPGPDecryptor();
		}
		return INSTANCE;
	}

	/**
	 * decrypts pgp encrypted bytes And verifies Signature.
	 *
	 * @param CipherIn
	 * @param privateKeyInput
	 * @param password
	 * @param isSigned
	 * @param publicKeyInput
	 * @return byte[] Decrypted
	 * @throws Exception
	 */
	public byte[] decryptAndVerifySignature(byte[] CipherIn, byte[] privateKeyInput, String password, boolean isSigned,
			byte[] publicKeyInput) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		InputStream in = new ByteArrayInputStream(CipherIn);
		final InputStream keyIn = new ByteArrayInputStream(privateKeyInput);
		final InputStream signingPublicKey = new ByteArrayInputStream(publicKeyInput);
		char[] passwordChar = password.toCharArray();
		in = PGPUtil.getDecoderStream(in);
		PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(in);
		PGPEncryptedDataList encryptedDataList;
		Object nextObject = pgpObjectFactory.nextObject();
		if (nextObject instanceof PGPEncryptedDataList) {
			encryptedDataList = (PGPEncryptedDataList) nextObject;
		} else {
			encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
		}
		Iterator<PGPPublicKeyEncryptedData> encryptedDataObjects = encryptedDataList.getEncryptedDataObjects();
		PGPPrivateKey pgpPrivateKey = null;
		PGPPublicKeyEncryptedData keyEncryptedData = null;
		while (pgpPrivateKey == null && encryptedDataObjects.hasNext()) {
			keyEncryptedData = encryptedDataObjects.next();
			pgpPrivateKey = BCPGPUtils.findPrivateKey(keyIn, keyEncryptedData.getKeyID(), passwordChar);
		}
		if (pgpPrivateKey == null) {
			throw new IllegalArgumentException("secret key for message not found.");
		}
		PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).setContentProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build(pgpPrivateKey);
		InputStream clearDataStream = keyEncryptedData.getDataStream(decryptorFactory);
		PGPObjectFactory objectFactory = new PGPObjectFactory(clearDataStream);
		Object message = objectFactory.nextObject();
		PGPObjectFactory pgpFact = null;
		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			pgpFact = new PGPObjectFactory(cData.getDataStream());
			message = pgpFact.nextObject();
		}
		PGPOnePassSignature pgpOnePassSignature = null;
		if (message instanceof PGPOnePassSignatureList) {
			if (isSigned) {
				PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) message;
				pgpOnePassSignature = onePassSignatureList.get(0);
				long keyId = pgpOnePassSignature.getKeyID();
				PGPPublicKey signerPublicKey = BCPGPUtils.readPublicKey(signingPublicKey, keyId);
				pgpOnePassSignature.initVerify(signerPublicKey, BouncyCastleProvider.PROVIDER_NAME);
			}
			message = pgpFact.nextObject();
		}
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		if (message instanceof PGPLiteralData) {
			PGPLiteralData pgpLiteralData = (PGPLiteralData) message;
			InputStream literalDataInputStream = pgpLiteralData.getInputStream();
			Streams.pipeAll(literalDataInputStream, output);
			if (isSigned) {
				pgpOnePassSignature.update(output.toByteArray());
				PGPSignatureList pgpSignatureList = (PGPSignatureList) pgpFact.nextObject();
				if (!pgpOnePassSignature.verify(pgpSignatureList.get(0))) {
					throw new PGPException("Signature verification failed!");
				}
			}
		} else {
			throw new PGPException("message is not a simple encrypted file - type unknown.");
		}
		return output.toByteArray();
	}

}