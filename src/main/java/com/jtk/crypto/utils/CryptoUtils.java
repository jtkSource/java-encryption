package com.jtk.crypto.utils;

import com.jtk.crypto.exception.JTKEncyptionException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
}
