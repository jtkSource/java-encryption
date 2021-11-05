package com.jtk.crypto.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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



}