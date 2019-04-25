package com.thunder.indika.utils.encryption.pgp;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
 * <p>
 * usage: RSAKeyPairGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class RSAKeyPairGenerator {
	public void exportKeyPair(
			OutputStream secretOut,
			OutputStream publicOut,
			PublicKey publicKey,
			PrivateKey privateKey,
			String identity,
			char[] passPhrase,
			boolean armor)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
		if (armor) {
			secretOut = new ArmoredOutputStream(secretOut);
		}

		PGPPublicKey pgpPublicKey = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date()));
		RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
		RSASecretBCPGKey rsaSecretBCPGKey = new RSASecretBCPGKey(rsaPrivateCrtKey.getPrivateExponent(), rsaPrivateCrtKey.getPrimeP(),
				rsaPrivateCrtKey.getPrimeQ());
		PGPPrivateKey pgpPrivateKey = new PGPPrivateKey(pgpPublicKey.getKeyID(), pgpPublicKey.getPublicKeyPacket(), rsaSecretBCPGKey);

		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyPair keyPair = new PGPKeyPair(pgpPublicKey, pgpPrivateKey);
		PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null,
				new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider(BouncyCastleProvider.PROVIDER_NAME)
						.build(passPhrase));

		secretKey.encode(secretOut);

		secretOut.close();

		if (armor) {
			publicOut = new ArmoredOutputStream(publicOut);
		}

		PGPPublicKey key = secretKey.getPublicKey();

		key.encode(publicOut);

		publicOut.close();
	}

}