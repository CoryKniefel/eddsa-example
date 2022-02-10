package com.corykniefel.eddsa.application;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class CertificatePrinterUtil {
    public static void printPemToFile(X509CertificateHolder x509CertificateHolder, String fileName) {
        String pem = getPemString(x509CertificateHolder);
            try (FileWriter fileWriter = new FileWriter("build/" + fileName + ".pem")) {
                fileWriter.write(pem);
                fileWriter.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
    }

    public static String getPemString(X509CertificateHolder x509CertificateHolder) {
        String result = "";
        StringWriter stringWriter = new StringWriter();

        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            PemObject pemObject = new PemObject("Certificate", x509CertificateHolder.getEncoded());
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            result = stringWriter.toString();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static void printToPkcs12(String fileName, X509CertificateHolder x509CertificateHolder, AsymmetricCipherKeyPair rootKeypair, String pw) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

            KeyPair keyPair = KeyUtil.convertToKeypair(rootKeypair);

            X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

            keyStore.load(null, null);

            keyStore.setKeyEntry("key", keyPair.getPrivate(), null, new Certificate[]{x509Certificate});

            FileOutputStream fOut = new FileOutputStream("build/" + fileName + ".p12");

            keyStore.store(fOut, pw.toCharArray());

            fOut.close();


        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
