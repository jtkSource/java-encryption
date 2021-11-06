package com.jtk.crypto.keystore;

import com.jtk.crypto.exception.JTKEncyptionException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class KeystoreManager {

    private static final Logger log = LoggerFactory.getLogger(KeystoreManager.class);

    private final KeyStore keystore;
    private final String fileName;
    private final char[] password;
    private final KeyStore.PasswordProtection keystorePassword;

    public KeystoreManager(String fileName, char[] password) {
        this.fileName = fileName;
        this.password = Arrays.copyOf(password, password.length);
        this.keystorePassword = new KeyStore.PasswordProtection(this.password);
        this.keystore = createKeystore();
    }

    /**
     * Used for storing symmetric keys
     *
     * @param credential - which is wrapped in what is called a ProtectionParam
     * @param alias      -  name  refer to the entry
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

    /**
     * Retrieve symmetric keys with alias
     *
     * @param alias -  name  refer to the entry
     * @return stored credentials
     */
    public String getSecret(String alias) {
        try {
            SecretKey secretKey = ((KeyStore.SecretKeyEntry) this.keystore.getEntry(alias, keystorePassword))
                    .getSecretKey();
            byte[] encoded = secretKey.getEncoded();
            return StringUtils.toEncodedString(encoded, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new JTKEncyptionException("Unable to get secret", e);
        }
    }

    /**
     * saving a trusted certificate
     *
     * @param alias       -  name  refer to the entry
     * @param certificate - certificate to be trusted
     */
    public void trustCertificate(String alias, Certificate certificate) {
        try {
            this.keystore.setCertificateEntry(alias, certificate);
            saveKeystore(this.keystore);
            log.info("Saved certificate:{}", alias);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new JTKEncyptionException("Couldn't save certificate", e);
        }
    }

    public Certificate getCertificate(String alias) {
        try {
            return keystore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new JTKEncyptionException("Unable to get Certificate", e);
        }
    }

    public void removeEntry(String alias) {
        try {

            keystore.deleteEntry(alias);
            saveKeystore(keystore);
            log.info("Removed Entry: {}", alias);

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new JTKEncyptionException("Unable to get Certificate", e);
        }
    }

    private KeyStore createKeystore() {
        try {
            File file = new File(fileName);
            char[] pwd = Arrays.copyOf(password, password.length);
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "SUN");
            if (file.exists()) {
                try (FileInputStream stream = new FileInputStream(file)) {
                    keyStore.load(stream, pwd);
                }
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

    private void saveKeystore(KeyStore keyStore) throws
            KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(fileName)) {
            keyStore.store(fileOutputStream, this.password);
        }
    }


}
