package com.jtk.crypto.utils;

import com.jtk.crypto.exception.JTKEncyptionException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class CryptoUtils {
    private static final Logger log = LoggerFactory.getLogger(CryptoUtils.class);

    /**
     * Initialization Vector, it is an arbitrary number which will be used
     * along with SecretKey during encryption.
     * The IV adds randomness to the start of the encryption process,
     * it is also called as nonce as it will be used only once.
     * SecureRandom class provides a cryptographically strong random number generator
     *
     * @param generatorAlgorithm
     * @param initializationVectorSizeInBits
     * @return
     */
    public static byte[] generateSalt(String generatorAlgorithm, int initializationVectorSizeInBits) {
        if (StringUtils.isEmpty(generatorAlgorithm)) {
            throw new JTKEncyptionException("GeneratorAlgorithm is empty");
        }
        try {
            SecureRandom random = SecureRandom.getInstance(generatorAlgorithm);
            byte[] iv = new byte[initializationVectorSizeInBits / 8];
            random.nextBytes(iv);
            log.debug("Generated salt {}", Base64.getEncoder().encodeToString(iv));
            return iv;
        } catch (NoSuchAlgorithmException e) {
            throw new JTKEncyptionException("Couldn't generate salt", e);
        }
    }

    public static SecretKey createSecretKey(char[] passphrase, byte[] salt,
                                            int iterationCount, int keySizeInBits,
                                            String keyDerivationFunction, String encryptionAlgo) {

        PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase, salt, iterationCount, keySizeInBits);
        SecretKey pbeKey;
        byte[] keyBytes = null;
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyDerivationFunction);
            pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
            keyBytes = pbeKey.getEncoded();
            return new SecretKeySpec(keyBytes, encryptionAlgo);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new JTKEncyptionException("Invalid exception", e);
        } finally {
            pbeKeySpec.clearPassword();
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    public static KeyPair generateRSAKeyPair(String generatorAlgorithm, int keySize) {
        if (StringUtils.isEmpty(generatorAlgorithm)) {
            throw new JTKEncyptionException("GeneratorAlgorithm is empty");
        }
        if (keySize < 2048) {
            throw new JTKEncyptionException("KeySize too small");
        }
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize, SecureRandom.getInstance(generatorAlgorithm));
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new JTKEncyptionException("Algo not found", e);
        }
    }

    public static X509Certificate loadCertificate(String fileName) {
        try (FileInputStream is = new FileInputStream(fileName)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return  (X509Certificate) certificateFactory.generateCertificate(is);
        } catch (CertificateException | IOException e) {
            throw new JTKEncyptionException("Unable to load certificate", e);
        }
    }

}
