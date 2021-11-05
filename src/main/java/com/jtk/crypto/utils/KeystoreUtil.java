package com.jtk.crypto.utils;

import com.jtk.crypto.exception.JTKEncyptionException;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class KeystoreUtil {

    private final KeyStore keystore;
    private String fileName;
    private char[] password;
    private KeyStore.PasswordProtection keystorePassword;

    public KeystoreUtil(String fileName, char[] password) {
        this.fileName = fileName;
        this.password = password;
        keystorePassword = new KeyStore.PasswordProtection(this.password);
        this.keystore = createKeystore();
    }

    /**
     * Used for storing symmetric keys
     * @param credential   - which is wrapped in what is called a ProtectionParam
     * @param alias -  name that we'll use in the future to refer to the entry
     */
    public void addSecret(char[] credential, String alias) {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBE");
            SecretKey generatedSecret =
                    secretKeyFactory.generateSecret(new PBEKeySpec(credential));
            this.keystore.setEntry(alias, new KeyStore.SecretKeyEntry(generatedSecret), keystorePassword);
            saveKeystore(this.keystore);
        } catch (NoSuchAlgorithmException | KeyStoreException | InvalidKeySpecException
                | IOException | CertificateException e) {
            e.printStackTrace();
        }
    }

    public String getSecret(String alias) {
        try {
            SecretKey secretKey = ((KeyStore.SecretKeyEntry)this.keystore.getEntry(alias, keystorePassword)).getSecretKey();
            byte[] encoded = secretKey.getEncoded();
            return StringUtils.toEncodedString(encoded, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new JTKEncyptionException("Unable to get secret", e);
        }
    }

    private KeyStore createKeystore() {
        try {
            File file = new File(fileName);
            char[] pwd = Arrays.copyOf(password, password.length);
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "SUN");
            if (file.exists()) {
                keyStore.load(new FileInputStream(file), pwd);
            } else {
                keyStore.load(null, pwd);
                saveKeystore(keyStore);
            }
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException
                | CertificateException | NoSuchProviderException e) {
            throw new JTKEncyptionException("Unexpected exception", e);
        }
    }

    private void saveKeystore(KeyStore keyStore) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        keyStore.store(new FileOutputStream(fileName), this.password);
    }

}
