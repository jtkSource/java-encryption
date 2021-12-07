package com.jtk.crypto.cert;

import com.jtk.crypto.keystore.KeystoreManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Properties;

class SelfSignedCertificateTest {
    private static final Logger log = LoggerFactory.getLogger(SelfSignedCertificateTest.class);
    private Properties properties;

    @BeforeEach
    public void setup() throws IOException {
        properties = new Properties();
        properties.load(new FileReader("src/test/resources/enc.properties"));
    }

    @Test
    @DisplayName("should match public keys when keystore is created with private key and a self signed certificate")
    public void test() {
        SelfSignedCertificate selfSignedCertificate = new SelfSignedCertificate(properties);
        X509Certificate cert = selfSignedCertificate.createCertificate();
        Assertions.assertNotNull(cert);
        KeystoreManager keystoreManager = new KeystoreManager("secrets/symm-pvt.pfx",
                "keystorepassword".toCharArray());
        keystoreManager.addPrivateKey(selfSignedCertificate.getKeyPair().getPrivate(), "keypass".toCharArray(),
                new X509Certificate[]{cert});

        KeystoreManager keystoreManager2 = new KeystoreManager("secrets/symm-pvt.pfx",
                "keystorepassword".toCharArray());

        PrivateKey pvtKey = keystoreManager2.getPrivateKey("keypass".toCharArray());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(pvtKey.getEncoded()),
                Base64.getEncoder().encodeToString(selfSignedCertificate.getPrivateKey().getEncoded()));

        Certificate cert1 = keystoreManager2.getCertificate("root");
        Assertions.assertEquals(cert.getPublicKey(), cert1.getPublicKey());
    }
}