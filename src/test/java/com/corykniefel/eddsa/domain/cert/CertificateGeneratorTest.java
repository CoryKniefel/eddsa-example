package com.corykniefel.eddsa.domain.cert;

import com.corykniefel.eddsa.application.CertificateGenerator;
import com.corykniefel.eddsa.application.KeyUtil;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CertificateGeneratorTest {

    @Test
    void createRoot() throws NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException {
        CertificateGenerator certGen = new CertificateGenerator();
        AsymmetricCipherKeyPair testAsymmetricKeyPair = KeyUtil.generateNewKeypair();
        KeyPair testKeyPair = KeyUtil.convertToKeypair(testAsymmetricKeyPair);
        String subjectName = "Root-CA";

        Optional<X509CertificateHolder> root = certGen.createSelfSignedRootCa(testAsymmetricKeyPair, subjectName, 10);

        assertTrue(root.isPresent());
        X509CertificateHolder holder = root.get();

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

        SubjectKeyIdentifier actualSki = extensionUtils.createSubjectKeyIdentifier(holder.getSubjectPublicKeyInfo());
        SubjectKeyIdentifier expectedSki = extensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(testAsymmetricKeyPair.getPublic()));
        assertTrue(actualSki.equals(expectedSki));

        AuthorityKeyIdentifier actualAuthorityKeyIdentifier = extensionUtils.createAuthorityKeyIdentifier(holder);
        AuthorityKeyIdentifier expectedAuthorityKeyIdentifier = extensionUtils.createAuthorityKeyIdentifier(testKeyPair.getPublic());
        assertTrue(actualAuthorityKeyIdentifier.toString().equals(expectedAuthorityKeyIdentifier.toString()));

        X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

        assertDoesNotThrow(() -> {
            x509Certificate.verify(testKeyPair.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        }, "Verifying the certificate does not throw exceptions");

        Extension basicConstraintsExt = holder.getExtension(Extension.basicConstraints);
        BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExt.getParsedValue());

        assertTrue(basicConstraints.isCA(), "The basic constraints for isCA is true");
        assertEquals(1, basicConstraints.getPathLenConstraint().intValue(), "The path length constraint is 1");

        assertEquals("CN=" + subjectName, x509Certificate.getIssuerDN().getName(), "The IssuerDN is expected");

        assertEquals("Ed25519", x509Certificate.getSigAlgName(), "The signature algorithm is Ed25519");

    }

    @Test
    void createIntermediateFromRootTest() throws NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException {
        CertificateGenerator certGen = new CertificateGenerator();
        AsymmetricCipherKeyPair caAsymmetricKeyPair = KeyUtil.generateNewKeypair();
        AsymmetricCipherKeyPair rootAsymmetricKeyPair = KeyUtil.generateNewKeypair();
        KeyPair caKeyPair = KeyUtil.convertToKeypair(caAsymmetricKeyPair);
        KeyPair rootKeyPair = KeyUtil.convertToKeypair(rootAsymmetricKeyPair);
        String subjectName = "Intermediate-CA";

        Optional<X509CertificateHolder> rootOptional = certGen.createSelfSignedRootCa(rootAsymmetricKeyPair, subjectName, 10);
        X509CertificateHolder rootHolder = rootOptional.orElseThrow();
        Optional<X509CertificateHolder> intermediate = certGen.createCaFromRoot(caAsymmetricKeyPair, subjectName, 10, rootHolder, rootKeyPair);

        assertTrue(intermediate.isPresent());
        X509CertificateHolder holder = intermediate.get();

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

        SubjectKeyIdentifier actualSki = extensionUtils.createSubjectKeyIdentifier(holder.getSubjectPublicKeyInfo());
        SubjectKeyIdentifier expectedSki = extensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(caAsymmetricKeyPair.getPublic()));
        assertTrue(actualSki.equals(expectedSki));

        AuthorityKeyIdentifier actualAuthorityKeyIdentifier = AuthorityKeyIdentifier.fromExtensions(holder.getExtensions());
        AuthorityKeyIdentifier expectedAuthorityKeyIdentifier = extensionUtils.createAuthorityKeyIdentifier(rootKeyPair.getPublic());
        assertTrue(actualAuthorityKeyIdentifier.toString().equals(expectedAuthorityKeyIdentifier.toString()));

        X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

        assertDoesNotThrow(() -> {
            x509Certificate.verify(rootKeyPair.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        }, "Verifying the certificate does not throw exceptions");

        Extension basicConstraintsExt = holder.getExtension(Extension.basicConstraints);
        BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExt.getParsedValue());

        assertTrue(basicConstraints.isCA(), "The basic constraints for isCA is true");
        assertEquals(0, basicConstraints.getPathLenConstraint().intValue(), "The path length constraint is 1");

        assertEquals("CN=" + subjectName, x509Certificate.getIssuerDN().getName(), "The IssuerDN is expected");

        assertEquals("Ed25519", x509Certificate.getSigAlgName(), "The signature algorithm is Ed25519");


    }

    @Test
    void getTimeForDaysInFuture() {
        CertificateGenerator certGen = new CertificateGenerator();
        int daysInFuture = 5;
        int oneDayLess = 4;
        int oneDayMore = 6;

        Date before = new Date(Duration.ofDays(oneDayLess).toMillis() + System.currentTimeMillis());
        Date after = new Date(Duration.ofDays(oneDayMore).toMillis() + System.currentTimeMillis());

        Time time = certGen.getTimeForDaysInFuture(daysInFuture);
        Date date = time.getDate();

        assertTrue(date.before(after), "The date is before");
        assertTrue(date.after(before), "The date is after");

    }

}