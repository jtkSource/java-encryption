package com.jtk.crypto.symmetric;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

@DisplayName("JTKCrypto Testing for encryption / decryption")
class JTKCryptoTest {

    private static final Logger log = LoggerFactory.getLogger(JTKCryptoTest.class);
    private Properties properties;

    @BeforeEach
    public void setup() throws IOException {
        properties = new Properties();
        properties.load(new FileReader("src/test/resources/enc.properties"));
    }

    @Test
    @DisplayName("should return encrypted text when correct properties are set")
    public void testEncryption() {
        JTKCrypto crypto = new JTKCrypto("passphrase".toCharArray(), properties);
        byte[] encryptedText = crypto.encryptMessage("Shush!! this is a secret");
        log.info("Ecrypted text {}", StringUtils.toEncodedString(encryptedText, StandardCharsets.UTF_8));
        Assertions.assertNotNull(encryptedText);
    }


    @Test
    @DisplayName("should return text when correct properties are set on encrypted text")
    public void testDencryption() {
        JTKCrypto crypto = new JTKCrypto("passphrase".toCharArray(), properties);
        byte[] encryptedText = crypto.encryptMessage("Shush!! this is a secret");
        String text = crypto.decryptMessage(encryptedText);
        log.info("Decrypted text {}", text);
        Assertions.assertEquals("Shush!! this is a secret", text);
        Assertions.assertNotNull(encryptedText);
    }

}