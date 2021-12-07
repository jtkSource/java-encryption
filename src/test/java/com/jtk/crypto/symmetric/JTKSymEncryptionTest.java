package com.jtk.crypto.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;
import java.util.Properties;

@DisplayName("JTKCrypto Testing for encryption / decryption")
class JTKSymEncryptionTest {
    private static final Logger log = LoggerFactory.getLogger(JTKSymEncryptionTest.class);
    private static Properties properties;

    @BeforeEach
    public void setup() throws IOException {
        properties = new Properties();
        properties.load(new FileReader("src/test/resources/enc.properties"));
    }

    @Test
    @DisplayName("should return encrypted text when correct properties are set")
    public void testEncryption() {
        JTKSymEncryption crypto = new JTKSymEncryption("passphrase".toCharArray(), properties);
        byte[] encryptedText = crypto.encryptMessage("Shush!! this is a secret");
        log.info("Ecrypted text {}", Base64.getEncoder().encodeToString(encryptedText));
        Assertions.assertNotNull(encryptedText);
    }

    @Test
    @DisplayName("should return text when correct properties are set on encrypted text")
    public void testDencryption() {
        JTKSymEncryption crypto = new JTKSymEncryption("passphrase".toCharArray(), properties);
        byte[] encryptedText = crypto.encryptMessage("Shush!! this is a secret");
        String text = crypto.decryptMessage(encryptedText);
        log.info("Decrypted text {}", text);
        Assertions.assertEquals("Shush!! this is a secret", text);
        Assertions.assertNotNull(encryptedText);
    }

    public static void main(String[] args) throws IOException {
        properties = new Properties();
        properties.load(new FileReader("src/test/resources/enc.properties"));
        char[] passphrase = args[0].toCharArray();
        String fileLinesToEncrypt = args[1];
        String destinationFiles = "src/test/resources/passphrases-enc";
        JTKSymEncryption crypto = new JTKSymEncryption(passphrase, properties);
        if(args.length == 3){
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(destinationFiles));
                 BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(fileLinesToEncrypt))) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    String encryptedText = crypto.decryptMessage(Base64.getDecoder().decode(line));
                    bufferedWriter.write(encryptedText + "\n");
                }
            } catch (Exception e) {
                log.error("Unexpected Exception", e);
            }

        }else {
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(fileLinesToEncrypt));
                 BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(destinationFiles))) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    byte[] encryptedText = crypto.encryptMessage(line);
                    bufferedWriter.write(Base64.getEncoder().encodeToString(encryptedText) + "\n");
                }
            } catch (Exception e) {
                log.error("Unexpected Exception", e);
            }
        }


    }

}