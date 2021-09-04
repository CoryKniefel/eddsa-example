package com.corykniefel.eddsa.domain.cert;

import com.corykniefel.eddsa.domain.ProjectConstants;
import com.corykniefel.eddsa.domain.key.KeyUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;

public class CertificateGenerator {
    private static long baseSerial = 1L;
    private final Logger logger = LogManager.getLogger();

    public Optional<X509CertificateHolder> createSelfSignedRootCa(AsymmetricCipherKeyPair rootKeypair, String name, int daysValid) {
        X509CertificateHolder result = null;
        try {
            KeyPair keyPair = KeyUtil.convertToKeypair(rootKeypair);
            X500Name x500Name = getName(name);
            SubjectPublicKeyInfo subjectPublicKeyInfo = getSubjectPublicKeyInfo(rootKeypair);

            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(x500Name,
                    getNextSerial(), getCurrentTime(),
                    getTimeForDaysInFuture(daysValid), x500Name, subjectPublicKeyInfo);

            addExtensionsRootCa(certificateBuilder, subjectPublicKeyInfo);

            ContentSigner signer = new JcaContentSignerBuilder(ProjectConstants.Ed25519).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
            result = certificateBuilder.build(signer);
            validateSignature(result);

        } catch (Exception e) {
            logger.error("Exception while create self signed root certificate", e);
        }

        return Optional.ofNullable(result);
    }

    public Optional<X509CertificateHolder> createCaFromRoot(AsymmetricCipherKeyPair asymmetricCaKeyPair, String name, int daysValid, X509CertificateHolder otherCa, KeyPair rootKeyPair) {
        X509CertificateHolder result = null;
        try {

            X500Name x500Name = getName(name);
            SubjectPublicKeyInfo subjectPublicKeyInfo = getSubjectPublicKeyInfo(asymmetricCaKeyPair);

            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(otherCa.getSubject(),
                    getNextSerial(), getCurrentTime(),
                    getTimeForDaysInFuture(daysValid), x500Name, subjectPublicKeyInfo);

            addExtensionsIntermediateCa(certificateBuilder, subjectPublicKeyInfo, otherCa);

            ContentSigner signer = new JcaContentSignerBuilder(ProjectConstants.Ed25519).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(rootKeyPair.getPrivate());
            result = certificateBuilder.build(signer);
            validateSignature(result);

        } catch (Exception e) {
            logger.error("Exception while create self signed root certificate", e);
        }

        return Optional.ofNullable(result);
    }

    private void validateSignature(X509CertificateHolder result) throws CertificateException, OperatorCreationException, CertException {
        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(result);
        result.isSignatureValid(contentVerifierProvider);
    }

    public Optional<X509CertificateHolder> createEeFromRoot(AsymmetricCipherKeyPair asymmetricCaKeyPair, String name, int daysValid, X509CertificateHolder otherCa, KeyPair rootKeyPair) {
        X509CertificateHolder result = null;
        try {

            X500Name x500Name = getName(name);
            SubjectPublicKeyInfo subjectPublicKeyInfo = getSubjectPublicKeyInfo(asymmetricCaKeyPair);

            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(otherCa.getSubject(),
                    getNextSerial(), getCurrentTime(),
                    getTimeForDaysInFuture(daysValid), x500Name, subjectPublicKeyInfo);

            addExtensionsEndEntity(certificateBuilder, subjectPublicKeyInfo, otherCa);

            ContentSigner signer = new JcaContentSignerBuilder(ProjectConstants.Ed25519).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(rootKeyPair.getPrivate());
            result = certificateBuilder.build(signer);
            validateSignature(result);

        } catch (Exception e) {
            logger.error("Exception while create self signed root certificate", e);
        }

        return Optional.ofNullable(result);

    }

    private void addExtensionsRootCa(X509v3CertificateBuilder certificateBuilder, SubjectPublicKeyInfo subjectPublicKeyInfo) {
        // this makes any certificate chain invalid if it contains more than one intermediate certificate
        // e.g. we're saying we want one intermediate certificate, no more
        int pathLength = 1;
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo);

            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, aki);
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLength));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

            Extensions extensions = extensionsGenerator.generate();
            for (ASN1ObjectIdentifier identifier : extensions.getExtensionOIDs()) {
                certificateBuilder.addExtension(extensions.getExtension(identifier));
            }

        } catch (NoSuchAlgorithmException | IOException e) {
            logger.error("Exception while adding extensions for root ca", e);
        }

    }

    private void addExtensionsIntermediateCa(X509v3CertificateBuilder certificateBuilder, SubjectPublicKeyInfo subjectPublicKeyInfo, X509CertificateHolder rootHolder) {
        // this makes any certificate chain invalid if it contains more than one intermediate certificate
        // e.g. we're saying we want zero intermediate certificates
        int pathLength = 0;
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(rootHolder);

            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, aki);
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLength));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

            Extensions extensions = extensionsGenerator.generate();
            for (ASN1ObjectIdentifier identifier : extensions.getExtensionOIDs()) {
                certificateBuilder.addExtension(extensions.getExtension(identifier));
            }

        } catch (NoSuchAlgorithmException | IOException e) {
            logger.error("Exception while adding extensions for intermediate ca", e);
        }

    }

    private void addExtensionsEndEntity(X509v3CertificateBuilder certificateBuilder, SubjectPublicKeyInfo subjectPublicKeyInfo, X509CertificateHolder caHolder) {
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
            AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(caHolder);

            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, aki);
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

            Extensions extensions = extensionsGenerator.generate();
            for (ASN1ObjectIdentifier identifier : extensions.getExtensionOIDs()) {
                certificateBuilder.addExtension(extensions.getExtension(identifier));
            }

        } catch (NoSuchAlgorithmException | IOException e) {
            logger.error("Exception while adding extensions for end entity ca", e);
        }
    }


    private SubjectPublicKeyInfo getSubjectPublicKeyInfo(AsymmetricCipherKeyPair aPublic) throws IOException {
        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(aPublic.getPublic());

    }

    Time getTimeForDaysInFuture(int days) {
        long millsInFuture = Duration.ofDays(days).plusMillis(System.currentTimeMillis()).toMillis();
        return new Time(new Date(millsInFuture));
    }

    Time getCurrentTime() {
        return new Time(new Date(System.currentTimeMillis()));
    }

    X500Name getName(String name) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, name).build();
        return builder.build();
    }

    public static synchronized BigInteger getNextSerial() {
        return BigInteger.valueOf(baseSerial++);
    }

}
