package com.corykniefel.eddsa.application;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws CertificateException {
        AsymmetricCipherKeyPair rootKeypair = KeyUtil.generateNewKeypair();
        AsymmetricCipherKeyPair intermediateKeypair = KeyUtil.generateNewKeypair();
        AsymmetricCipherKeyPair endEntityKeypair = KeyUtil.generateNewKeypair();

        CertificateGenerator certGenerator = new CertificateGenerator();

        int daysValid = 10;
        String rootName = "Root";
        String intermediateName = "Intermediate";
        String endEntityName = "EndEntity";
        String pw = "changeit";

        X509CertificateHolder rootHolder = certGenerator.createSelfSignedRootCa(rootKeypair, rootName, daysValid)
                .orElseThrow(() -> new RuntimeException("End-entity certificate was not created. The certificate chain will not be validated"));

        CertificatePrinterUtil.printPemToFile(rootHolder, rootName);
        CertificatePrinterUtil.printToPkcs12(rootName, rootHolder, rootKeypair, pw);
        System.out.println("Root certificate: \n" + CertificatePrinterUtil.getPemString(rootHolder));

        X509CertificateHolder caHolder = certGenerator.createCaFromRoot(intermediateKeypair, intermediateName, daysValid, rootHolder, KeyUtil.convertToKeypair(rootKeypair))
                .orElseThrow(() -> new RuntimeException("Intermediate certificate was not created. No other certificates will be created"));

        CertificatePrinterUtil.printPemToFile(caHolder, intermediateName);
        CertificatePrinterUtil.printToPkcs12(intermediateName, caHolder, intermediateKeypair, pw);
        System.out.println("Intermediate signing certificate: \n" + CertificatePrinterUtil.getPemString(caHolder));


        X509CertificateHolder endEntity = certGenerator.createEeFromRoot(endEntityKeypair, endEntityName, daysValid, caHolder, KeyUtil.convertToKeypair(intermediateKeypair))
                .orElseThrow(() -> new RuntimeException("Root certificate was not created. No other certificates will be created"));

        CertificatePrinterUtil.printPemToFile(endEntity, endEntityName);
        CertificatePrinterUtil.printToPkcs12(endEntityName, endEntity, intermediateKeypair, pw);
        System.out.println("End entity certificate: \n" + CertificatePrinterUtil.getPemString(caHolder));

        validateCertChain(rootHolder, caHolder, endEntity);


    }

    public static void validateCertChain(X509CertificateHolder root, X509CertificateHolder intermediate, X509CertificateHolder endEntity) throws CertificateException {

        Validate validate = new Validate();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

        List<Certificate> certificateList = new ArrayList<>();
        certificateList.add(converter.getCertificate(endEntity));
        certificateList.add(converter.getCertificate(intermediate));
        certificateList.add(converter.getCertificate(root));

        TrustAnchor anchor = new TrustAnchor(converter.getCertificate(root), null);

        validate.validatePath(certificateList, anchor);


    }
}
