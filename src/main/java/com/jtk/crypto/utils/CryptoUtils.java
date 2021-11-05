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
