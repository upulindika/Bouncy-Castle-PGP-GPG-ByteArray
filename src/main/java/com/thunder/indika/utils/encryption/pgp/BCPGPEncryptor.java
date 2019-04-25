package com.thunder.indika.utils.encryption.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * Provides encrypt and sign method using bouncy castle library.
 * supports Open PGP, GPG cryptographic systems.
 */
public class BCPGPEncryptor {

	private static BCPGPEncryptor INSTANCE = null;

	private BCPGPEncryptor() {
	}

	public static BCPGPEncryptor getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new BCPGPEncryptor();
		}
		return INSTANCE;
	}

	/**
	 * Encrypts And Sign bytes using bouncy castle library.
	 *
	 * @param input
	 * @param publicKey
	 * @param isSigning
	 * @param signingPvtKey
	 * @param signingPrivateKeyPassword
	 * @param isArmored
	 * @return byte[] Encrypted
	 * @throws PGPException
	 */
	public byte[] encryptAndSign(byte[] input, byte[] publicKey, boolean isSigning, byte[] signingPvtKey, String signingPrivateKeyPassword,
			boolean isArmored)
			throws PGPException {
		try {
			Security.addProvider(new BouncyCastleProvider());
			final ByteArrayInputStream inputFile = new ByteArrayInputStream(input);
			final ByteArrayInputStream publicKeyInput = new ByteArrayInputStream(publicKey);
			final ByteArrayInputStream signingPrivateKey = new ByteArrayInputStream(signingPvtKey);

			PGPPublicKey pgpPublicKey = BCPGPUtils.readPublicKey(publicKeyInput);
			final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
							.setSecureRandom(new SecureRandom()).setProvider(BouncyCastleProvider.PROVIDER_NAME));
			encryptedDataGenerator
					.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider(BouncyCastleProvider.PROVIDER_NAME));
			ByteArrayOutputStream bytesOutput = new ByteArrayOutputStream();
			OutputStream fileOutStream = bytesOutput;
			if (isArmored) {
				fileOutStream = new ArmoredOutputStream(fileOutStream);
			}

			OutputStream encryptdOutStream = encryptedDataGenerator.open(fileOutStream, new byte[1 << 16]);
			PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			OutputStream compressedOutStream = compressedDataGenerator.open(encryptdOutStream);
			PGPSignatureGenerator pgpSignatureGenerator = null;
			if (isSigning) {
				PGPSecretKey pgpSecretKey = BCPGPUtils.findSecretKey(signingPrivateKey);
				PGPPrivateKey pgpPrivateKey = pgpSecretKey
						.extractPrivateKey(signingPrivateKeyPassword.toCharArray(), BouncyCastleProvider.PROVIDER_NAME);
				pgpSignatureGenerator = new PGPSignatureGenerator(pgpSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1,
						BouncyCastleProvider.PROVIDER_NAME);
				pgpSignatureGenerator.initSign(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);
				Iterator userIDs = pgpSecretKey.getPublicKey().getUserIDs();
				if (userIDs.hasNext()) {
					PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
					subpacketGenerator.setSignerUserID(false, (String) userIDs.next());
					pgpSignatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
				}
				pgpSignatureGenerator.generateOnePassVersion(false).encode(compressedOutStream);
			}

			PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
			OutputStream literalDataOutStream = literalDataGenerator
					.open(compressedOutStream, PGPLiteralData.BINARY, "filename", inputFile.available(), new Date());

			byte[] bytes = IOUtils.toByteArray(inputFile);

			literalDataOutStream.write(bytes);
			if (isSigning) {
				pgpSignatureGenerator.update(bytes);
				pgpSignatureGenerator.generate().encode(compressedOutStream);
			}
			literalDataOutStream.close();
			literalDataGenerator.close();
			compressedOutStream.close();
			compressedDataGenerator.close();
			encryptedDataGenerator.close();
			fileOutStream.close();
			return bytesOutput.toByteArray();
		} catch (Exception e) {
			throw new PGPException("Error occurred while encrypting", e);
		}
	}

}