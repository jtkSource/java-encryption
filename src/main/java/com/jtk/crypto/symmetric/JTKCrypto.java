package com.jtk.crypto.symmetric;

import com.jtk.crypto.exception.JTKEncyptionException;
import com.jtk.crypto.utils.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Properties;

public class JTKCrypto {
    private static final Logger log = LoggerFactory.getLogger(JTKCrypto.class);
    private final int iterationCount;
    private final int keySizeInBits;
    private final String keyDerivationFunction;
    private final String encryptionAlgo;
    private final String generatorAlgorithm;
    private final int initializationVectorSizeInBits;
    private final int tagSizeInBits;
    private final String transformationAlgo;

    private char[] passphrase;
    private Properties properties;

    public JTKCrypto(char[] passphrase, Properties properties) {
        this.passphrase = Arrays.copyOf(passphrase, passphrase.length);
        this.properties = new Properties();
        properties.keySet()
                .stream()
                .forEach(key -> this.properties.setProperty((String) key, properties.getProperty((String) key)));
        iterationCount = Integer.parseInt(properties.getProperty("jtk.encryption.iteration.count", "250"));
        keySizeInBits = Integer.parseInt(properties.getProperty("jtk.encryption.key.size.in.bits", "128"));
        keyDerivationFunction = properties.getProperty("jtk.encryption.key.derivation.function");
        encryptionAlgo = properties.getProperty("jtk.encryption.algorithm", "AES");
        generatorAlgorithm = properties.getProperty("jtk.encryption.generator.algorithm");
        initializationVectorSizeInBits = Integer.parseInt(properties.getProperty("jtk.encryption.iv.size.in.bits"));
        tagSizeInBits = Integer.parseInt(properties.getProperty("jtk.encryption.tag.size.in.bits"));
        transformationAlgo = properties.getProperty("jtk.encryption.transformation");

        log.info("Initialized JTKCrypto");
    }

    public byte[] encryptMessage(Serializable serializable) {
        if (serializable == null) {
            throw new JTKEncyptionException("Object is null");
        }
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            ObjectOutputStream outputStream = new ObjectOutputStream(bos);
            outputStream.writeObject(serializable);
            outputStream.flush();
            return encrypt(bos.toByteArray());
        } catch (IOException e) {
            throw new JTKEncyptionException("Couldn't encrypt serializable message", e);
        }
    }

    public <T extends Serializable> T decryptMessage(byte[] encryptedText) {
        if (encryptedText == null || encryptedText.length == 0) {
            throw new JTKEncyptionException("Exception is null length");
        }
        try (ByteArrayInputStream bis = new ByteArrayInputStream(decrypt(encryptedText))) {
            ObjectInput in = new ObjectInputStream(bis);
            return (T) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new JTKEncyptionException("Couldn't serialize message", e);
        }
    }

    private byte[] decrypt(byte[] encryptedText) {
        byte[] salt = Arrays.copyOfRange(encryptedText, 0, initializationVectorSizeInBits / 8);
        byte[] cipherText = Arrays.copyOfRange(encryptedText, salt.length, encryptedText.length);
        byte[] message;
        try {
            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, passphrase, salt);
            message = cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new JTKEncyptionException("Couldn't decrypt  message", e);
        }
        return message;
    }

    private byte[] encrypt(byte[] bytes) {
        byte[] cipherText;
        try {
            byte[] salt = CryptoUtils.generateSalt(generatorAlgorithm, initializationVectorSizeInBits);
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, this.passphrase, salt);
            cipherText = cipher.doFinal(bytes);
            byte[] result = new byte[salt.length + cipherText.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(cipherText, 0, result, salt.length, cipherText.length);
            return result;
        } catch (Exception e) {
            throw new JTKEncyptionException("Could encrypt message", e);
        }
    }

    private Cipher initCipher(int encryptMode, char[] passphrase, byte[] salt) {
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagSizeInBits, salt);
        SecretKey key = createSecretKey(passphrase, salt);
        try {
            Cipher cipher = Cipher.getInstance(transformationAlgo);
            cipher.init(encryptMode, key, gcmParameterSpec);
            return cipher;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new JTKEncyptionException("Couldnt create Cipher Instance", e);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new JTKEncyptionException("Couldnt initialize Cipher Instance", e);
        }
    }

    private SecretKey createSecretKey(char[] passphrase, byte[] salt) {
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
}
