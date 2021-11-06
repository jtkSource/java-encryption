package com.jtk.crypto.keystore;

import com.jtk.crypto.utils.CryptoUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

class KeystoreManagerTest {

    @Test
    @DisplayName("should store symmetric key in keystore when processed")
    public void testSymmetricKey() {
        char[] storepassword = "blah-blah".toCharArray();
        KeystoreManager keystoreUtil = new KeystoreManager("secrets/symm.pfx", storepassword);
        keystoreUtil.addSecret("secret-cred".toCharArray(), "some-secret");
        KeystoreManager ks = new KeystoreManager("secrets/symm.pfx", storepassword);
        Assertions.assertEquals("secret-cred", ks.getSecret("some-secret"));
    }

    @Test
    public void testLoadCertificate() {
        X509Certificate cer = CryptoUtils.loadCertificate("secrets/stackoverflow.cer");
        Assertions.assertNotNull(cer.getPublicKey());
        char[] storepassword = "blah-blah".toCharArray();
        KeystoreManager keystoreUtil = new KeystoreManager("secrets/symm-trust.pfx", storepassword);
        keystoreUtil.trustCertificate("stackoverflow", cer);
        Certificate stackCer = keystoreUtil.getCertificate("stackoverflow");
        Assertions.assertNotNull(stackCer);
    }


}