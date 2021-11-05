package com.jtk.crypto.utils;

import com.jtk.crypto.exception.JTKEncyptionException;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

@DisplayName("Crypto Utilities Test")
class CryptoUtilsTest {

    @Test
    @DisplayName("should generate salt when initialization vector and generator algo specified")
    public void testSalt() {
        byte[] salt = CryptoUtils.generateSalt("DRBG", 128);
        Assertions.assertNotNull(salt);
    }

    @Test
    @DisplayName("should throw exception when invalid generator algo specified")
    public void testSaltException() {
        Assertions.assertThrows(JTKEncyptionException.class, () ->
                CryptoUtils.generateSalt(null, 16));
    }

    @Test
    @DisplayName("should return keypair when keypair generator is called with SecureRandom algo DRGB and keysize 3098")
    public void testKeyPairGen(){
        KeyPair kp = CryptoUtils.generateRSAKeyPair("DRBG", 3098);
        Assertions.assertNotNull(kp.getPrivate());
        Assertions.assertNotNull(kp.getPublic());
    }

}