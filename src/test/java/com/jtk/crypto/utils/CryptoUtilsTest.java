package com.jtk.crypto.utils;

import com.jtk.crypto.exception.JTKEncyptionException;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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

}