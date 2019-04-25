package com.thunder.indika.utils.encryption.pgp;

/**
 * Test data for TestBCOpenPGP
 */
public class BCPGPTestData {

	public static final String senderPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
			//TODO - Add Sender Public Key
			+ "-----END PGP PUBLIC KEY BLOCK-----";

	public static final String senderPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
			//TODO - Add Sender Private Key
			+ "-----END PGP PRIVATE KEY BLOCK-----";

	public static final String senderPassword = "SenderPassword";

	public static final String receiverPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
			//TODO - Add receiver Public Key
			+ "-----END PGP PUBLIC KEY BLOCK-----";

	public static final String receiverPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
			//TODO - Add receiver Private Key
			+ "-----END PGP PRIVATE KEY BLOCK-----";

	public static final String receiverPassword = "ReceiverPassword";

	public static final String clearPayload = "Clear Text";

	public static final String encryptedPayload = "-----BEGIN PGP MESSAGE-----\n"
			+ "Version: BCPG v1.50\n"
			//TODO - Add encrypted Message
			+ "-----END PGP MESSAGE-----";

	public static final String badsignaturePayload = "-----BEGIN PGP MESSAGE-----\n"
			+ "Version: BCPG v1.50\n"
			//TODO - Add Unsigned Message
			+ "-----END PGP MESSAGE-----";

	public static final String secondreceiverPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
			+ "-----END PGP PRIVATE KEY BLOCK-----";

	public static final String secondreceiverPassword = "SecondReceiverPassword";

	public static final String secondSendersPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
			//TODO - Add Second Senders Public Key
			+ "-----END PGP PUBLIC KEY BLOCK-----";
}
