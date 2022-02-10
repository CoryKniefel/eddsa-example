package com.corykniefel.eddsa.application;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyUtil {

    private final static Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
    public final static Logger logger = LogManager.getLogger();

    static {
        SecureRandom RANDOM = new SecureRandom();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(RANDOM));
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair convertToKeypair(AsymmetricCipherKeyPair asymmetricCipherKeyPair) {
        KeyPair result = null;

        PKCS8EncodedKeySpec privateKeyInfoEncodedKeySpec = null;
        X509EncodedKeySpec publicKeyInfoEncodedKeySpec = null;
        KeyFactory keyFactory = null;

        try {
            keyFactory = KeyFactory.getInstance(ProjectConstants.Ed25519, BouncyCastleProvider.PROVIDER_NAME);

            byte[] privateKeyInfoEncoded = PrivateKeyInfoFactory.createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate()).getEncoded();
            privateKeyInfoEncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyInfoEncoded);

            byte[] publicKeyInfoEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic()).getEncoded();
            publicKeyInfoEncodedKeySpec = new X509EncodedKeySpec(publicKeyInfoEncoded);

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeyInfoEncodedKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeyInfoEncodedKeySpec);

            result = new KeyPair(publicKey, privateKey);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            logger.error("Exception converting a keypair.", e);
        }

        return result;
    }

    public static AsymmetricCipherKeyPair generateNewKeypair() {
        return keyPairGenerator.generateKeyPair();
    }

    public static Ed25519PublicKeyParameters getPublicKeyParameter(AsymmetricCipherKeyPair asymmetricCipherKeyPair) {
        return (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();
    }

    public static Ed25519PrivateKeyParameters getPrivateKeyParameter(AsymmetricCipherKeyPair asymmetricCipherKeyPair) {
        return (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
    }
}
