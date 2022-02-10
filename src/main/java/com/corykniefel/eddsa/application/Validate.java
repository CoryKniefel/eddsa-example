package com.corykniefel.eddsa.application;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.List;
import java.util.Set;

public class Validate {
    private final Logger logger = LogManager.getLogger();

    public void validatePath(List<Certificate> certificates, TrustAnchor trustAnchor) {

        try {

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certificateFactory.generateCertPath(certificates);
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            PKIXParameters certPathParameters = new PKIXParameters(Set.of(trustAnchor));
            certPathParameters.setRevocationEnabled(false);

            CertPathValidatorResult certPathValidatorResult = certPathValidator.validate(certPath, certPathParameters);

            logger.info("Certificate path is valid \n" + certPathValidatorResult.toString());


        } catch (NoSuchAlgorithmException | CertificateException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
            logger.error("Certificate path validation failed", e);

            if (e instanceof CertPathValidatorException) {
                int pathIndexError = ((CertPathValidatorException) e).getIndex();
                logger.error("The index is: " + pathIndexError);
            }

        }
    }
}
