package com.jtk.crypto.cert;

import com.jtk.crypto.exception.JTKEncyptionException;
import com.jtk.crypto.utils.CryptoUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

public class SelfSignedCertificate {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final Properties properties = new Properties();
    private final int keySize;
    private final KeyPair keyPair;
    private final X500Name subject;
    private final ContentSigner signatureGenerator;

    public SelfSignedCertificate(Properties properties) {
        properties.forEach((key, value) -> this.properties.setProperty((String) key, (String) value));
        keySize = Integer.parseInt(this.properties.getProperty("jtk.keypair.key.size"));
        keyPair = CryptoUtils
                .generateRSAKeyPair(this.properties.getProperty("jtk.cert.generator.algorithm"),
                        keySize);
        subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, this.properties.getProperty("jtk.cert.subject.fqdn","localhost"))
                .addRDN(BCStyle.OU, this.properties.getProperty("jtk.cert.subject.ou","test"))
                .addRDN(BCStyle.O, this.properties.getProperty("jtk.cert.subject.organization","test"))
                .addRDN(BCStyle.L, this.properties.getProperty("jtk.cert.subject.location","test"))
                .addRDN(BCStyle.ST, this.properties.getProperty("jtk.cert.subject.state","test"))
                .addRDN(BCStyle.C, this.properties.getProperty("jtk.cert.subject.country","test"))
                .addRDN(BCStyle.EmailAddress, this.properties.getProperty("jtk.cert.subject.email","some"))
                .build();
        try {
            signatureGenerator = new JcaContentSignerBuilder(this.properties.getProperty("jtk.cert.sign.algo"))
                    .setProvider("BC")
                    .build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new JTKEncyptionException("Unexpected Exception", e);
        }
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public PrivateKey getPrivateKey(){
        return keyPair.getPrivate();
    }

    public X509Certificate createCertificate() {
        try {
            Date notBefore = new Date(System.currentTimeMillis() - 1 * 24 * 60 * 60 * 1000L);
            Date notAfter = new Date(System.currentTimeMillis() + 5 * 365 * 24 * 60 * 60 * 1000L);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certificateBuilder.build(signatureGenerator));
            certificate.checkValidity(new Date());
            certificate.verify(certificate.getPublicKey());
            return certificate;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new JTKEncyptionException("Unexpected Exception", e);
        }
    }
}
