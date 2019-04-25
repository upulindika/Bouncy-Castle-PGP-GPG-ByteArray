package com.thunder.indika.utils.encryption.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * Utility Class that provides commonly used methods for Bouncy-castle encryption decryption.
 */
public abstract class BCPGPUtils {

	/**
	 * Reads PGPPublicKey by given public key.
	 *
	 * @param in
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(in);
		PGPPublicKey pgpPublicKey = null;
		Iterator keyRings = keyRingCollection.getKeyRings();
		while (pgpPublicKey == null && keyRings.hasNext()) {
			PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) keyRings.next();
			Iterator publicKeys = publicKeyRing.getPublicKeys();
			while (pgpPublicKey == null && publicKeys.hasNext()) {
				PGPPublicKey publicKey = (PGPPublicKey) publicKeys.next();
				if (publicKey.isEncryptionKey()) {
					pgpPublicKey = publicKey;
				}
			}
		}
		if (pgpPublicKey == null) {
			throw new IllegalArgumentException(
					"Can not find encryption key in key ring.");
		}
		return pgpPublicKey;
	}

	/**
	 * Reads PGPPublicKey by given public key and keyId.
	 *
	 * @param in
	 * @param keyId
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPublicKey readPublicKey(InputStream in, long keyId) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(in);
		PGPPublicKey pgpPublicKey = null;
		Iterator keyRings = keyRingCollection.getKeyRings();
		while (keyRings.hasNext()) {
			PGPPublicKeyRing pgpPublicKeyRing = (PGPPublicKeyRing) keyRings.next();
			Iterator publicKeys = pgpPublicKeyRing.getPublicKeys();
			while (publicKeys.hasNext()) {
				PGPPublicKey nextPGPPubKey = (PGPPublicKey) publicKeys.next();
				long pubKeyKeyID = nextPGPPubKey.getKeyID();
				if (pubKeyKeyID == keyId) {
					pgpPublicKey = nextPGPPubKey;
				}
			}
		}
		if (pgpPublicKey == null) {
			throw new IllegalArgumentException(
					"Can not find encryption key in key ring.");
		}
		return pgpPublicKey;
	}

	/**
	 * Finds PGPPrivateKey by given private-key, keyID and Pass phrase.
	 *
	 * @param keyIn
	 * @param keyID
	 * @param pass
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID,
			char[] pass) throws IOException, PGPException {
		PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
		PGPSecretKey pgpSecretKey = secretKeyRingCollection.getSecretKey(keyID);
		if (pgpSecretKey == null) {
			return null;
		}
		PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder(
				new JcaPGPDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pass);
		return pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
	}

	/**
	 * Finds PGPSecretKey by given private key.
	 *
	 * @param in
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPSecretKey findSecretKey(InputStream in) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(in);
		PGPSecretKey pgpSecretKey = null;
		Iterator keyRings = secretKeyRingCollection.getKeyRings();
		while (pgpSecretKey == null && keyRings.hasNext()) {
			PGPSecretKeyRing pgpSecretKeyRing = (PGPSecretKeyRing) keyRings.next();
			Iterator secretKeys = pgpSecretKeyRing.getSecretKeys();
			while (pgpSecretKey == null && secretKeys.hasNext()) {
				PGPSecretKey secretKey = (PGPSecretKey) secretKeys.next();

				if (secretKey.isSigningKey()) {
					pgpSecretKey = secretKey;
				}
			}
		}
		if (pgpSecretKey == null) {
			throw new IllegalArgumentException(
					"Can not find signing key in key ring.");
		}
		return pgpSecretKey;
	}
}
