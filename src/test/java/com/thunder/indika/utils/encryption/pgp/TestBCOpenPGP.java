package com.thunder.indika.utils.encryption.pgp;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Assert;
import org.junit.Test;

public class TestBCOpenPGP {
	ClassLoader classLoader = getClass().getClassLoader();
	private boolean isArmored = true;
	private boolean isSigned = true;
	private String id = "testId";
	private String password = "testpassword";
	private String pubKeyFile = classLoader.getResource("publicKey.gpg").getFile();
	private String privKeyFile = classLoader.getResource("privateKey.gpg").getFile();

	@Test
	public void generateKeyPair()
			throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {
		RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		FileOutputStream pkOutputStream = new FileOutputStream(privKeyFile);
		FileOutputStream pubOutputStream = new FileOutputStream(pubKeyFile);
		rsaKeyPairGenerator
				.exportKeyPair(pkOutputStream, pubOutputStream, keyPair.getPublic(), keyPair.getPrivate(), id, password.toCharArray(),
						isArmored);
	}

	@Test
	public void encryptAndSign() throws Exception {
		byte[] encryptedBytes = BCPGPEncryptor.getInstance()
				.encryptAndSign(BCPGPTestData.clearPayload.getBytes(), BCPGPTestData.receiverPublicKey.getBytes(), isSigned,
						BCPGPTestData.senderPrivateKey.getBytes(), BCPGPTestData.senderPassword, isArmored);
		String encryptedText = new String(encryptedBytes);
		Assert.assertNotNull(encryptedBytes);
		Assert.assertTrue(encryptedText.startsWith("-----BEGIN PGP MESSAGE-----"));
		Assert.assertTrue(encryptedText.contains("-----END PGP MESSAGE-----"));
	}

	@Test
	public void decryptAndVerifySignature() throws Exception {
		byte[] decryptedBytes = BCPGPDecryptor.getInstance()
				.decryptAndVerifySignature(BCPGPTestData.encryptedPayload.getBytes(), BCPGPTestData.receiverPrivateKey.getBytes(),
						BCPGPTestData.receiverPassword, isSigned, BCPGPTestData.senderPublicKey.getBytes());
		String decryptedPayload = new String(decryptedBytes);
		Assert.assertTrue(decryptedPayload.startsWith("Clear"));
		Assert.assertTrue(decryptedPayload.endsWith("Text"));
		Assert.assertTrue(decryptedPayload.contains("Clear Text"));
	}

	@Test(expected = PGPException.class )
	public void expectSignatureVerificationFailure() throws Exception {
		byte[] decryptedBytes = BCPGPDecryptor.getInstance()
				.decryptAndVerifySignature(BCPGPTestData.badsignaturePayload.getBytes(), BCPGPTestData.secondreceiverPrivateKey.getBytes(),
						BCPGPTestData.secondreceiverPassword, isSigned, BCPGPTestData.secondSendersPublicKey.getBytes());
	}

}