package com.jtk.crypto.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

class KeystoreUtilTest {

    @Test
    @DisplayName("should store symmetric key in keystore when processed")
    public void testSymmetricKey() {
        char[] storepassword = "blah-blah".toCharArray();
        KeystoreUtil keystoreUtil = new KeystoreUtil("secrets/symm.pfx", storepassword);
        keystoreUtil.addSecret("secret-cred".toCharArray(), "some-secret");
        KeystoreUtil ks = new KeystoreUtil("secrets/symm.pfx", storepassword);
        Assertions.assertEquals("secret-cred", ks.getSecret("some-secret"));
    }

    @Test
    public void testLoadCertificate() {
        X509Certificate cer = CryptoUtils.loadCertificate("secrets/stackoverflow.cer");
        Assertions.assertNotNull(cer.getPublicKey());
        char[] storepassword = "blah-blah".toCharArray();
        KeystoreUtil keystoreUtil = new KeystoreUtil("secrets/symm-trust.pfx", storepassword);
        keystoreUtil.trustCertficate("stackoverflow", cer);
        Certificate stackCer = keystoreUtil.getCerificate("stackoverflow");
        Assertions.assertNotNull(stackCer);
    }


}