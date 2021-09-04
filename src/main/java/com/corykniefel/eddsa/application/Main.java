package com.corykniefel.eddsa.application;

import com.corykniefel.eddsa.domain.cert.CertificateGenerator;
import com.corykniefel.eddsa.domain.cert.CertificatePrinterUtil;
import com.corykniefel.eddsa.domain.key.KeyUtil;
import com.corykniefel.eddsa.domain.validate.Validate;
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

    private final static Logger logger = LogManager.getLogger();

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

        Optional<X509CertificateHolder> rootHolderO = certGenerator.createSelfSignedRootCa(rootKeypair, rootName, daysValid);

        if (rootHolderO.isPresent()) {
            X509CertificateHolder rootHolder = rootHolderO.get();
            CertificatePrinterUtil.printPemToFile(rootHolder, rootName);
            CertificatePrinterUtil.printToPkcs12(rootName, rootHolder, rootKeypair, pw);

            Optional<X509CertificateHolder> caHolderO = certGenerator.createCaFromRoot(intermediateKeypair, intermediateName, daysValid, rootHolder, KeyUtil.convertToKeypair(rootKeypair));

            if (caHolderO.isPresent()) {
                X509CertificateHolder caHolder = caHolderO.get();
                CertificatePrinterUtil.printPemToFile(caHolder, intermediateName);
                CertificatePrinterUtil.printToPkcs12(intermediateName, caHolder, intermediateKeypair, pw);

                Optional<X509CertificateHolder> endEntityHolderO = certGenerator.createEeFromRoot(endEntityKeypair, endEntityName, daysValid, caHolder, KeyUtil.convertToKeypair(intermediateKeypair));

                if (endEntityHolderO.isPresent()) {
                    X509CertificateHolder endEntity = endEntityHolderO.get();
                    CertificatePrinterUtil.printPemToFile(endEntity, endEntityName);
                    CertificatePrinterUtil.printToPkcs12(endEntityName, endEntity, intermediateKeypair, pw);

                    validateCertChain(rootHolder, caHolder, endEntity);


                } else {
                    logger.error("End-entity certificate was not created. The certificate chain will not be validated");
                }
            } else {
                logger.error("Intermediate certificate was not created. No other certificates will be created");
            }
        } else {
            logger.error("Root certificate was not created. No other certificates will be created");
        }


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
