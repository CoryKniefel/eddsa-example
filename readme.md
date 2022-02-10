# EdDSA Example 
This program creates X.509 V3 certificates using the Ed25519 algorithm,
the Bouncy Castle API, and Java Security features.  

### Builds Certificates
A self-signed root certificate authority, an intermediate certificate authority 
and an end-entity certificate are created.

### Exports the Certificates
Each certificate is exported to disk as a PEM file as a public key certificate, 
as well as a PKCS12 keystore containing
the private key and public certificate.

### Validates the Certificate Chain 

A certificate path is built using the 3 certificates and validation is performed, proving the path is valid. 
The result of the validation is logged to the console; it looks similar to this: 

```
Root certificate:  
-----BEGIN Certificate-----
MIIBMjCB5aADAgECAgEBMAUGAytlcDAPMQ0wCwYDVQQDDARSb290MB4XDTIyMDIx
MDA0NTYxMFoXDTIyMDIyMDA0NTYxMFowDzENMAsGA1UEAwwEUm9vdDAqMAUGAytl
cAMhAKoBjAMjeP5PCaJK11FnVfW5yMsxcYVUec6B9qxc8Bsqo2YwZDAdBgNVHQ4E
FgQUxwsLwVA43JNXigUVuWmaVuw1GDUwHwYDVR0jBBgwFoAUxwsLwVA43JNXigUV
uWmaVuw1GDUwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAgQwBQYD
K2VwA0EABqYvvLPBWQQdNlDxJekL0+iCIBayRZ4YtGDWZ67wQSOXNn+fN2QxKi4S
v/3e8WEueJNT3TK3XV1eyxk/S66LBA==
-----END Certificate-----

Intermediate signing certificate:
-----BEGIN Certificate-----
MIIBUzCCAQWgAwIBAgIBAjAFBgMrZXAwDzENMAsGA1UEAwwEUm9vdDAeFw0yMjAy
MTAwNDU2MTBaFw0yMjAyMjAwNDU2MTBaMBcxFTATBgNVBAMMDEludGVybWVkaWF0
ZTAqMAUGAytlcAMhAIyY0AMf4JElyRO6flvl9y+yv+6V0Vdf76rNvQxxN6E8o34w
fDAdBgNVHQ4EFgQUu3fA9rdpTulUskoB8nskWdVLwWcwNwYDVR0jBDAwLoAUxwsL
wVA43JNXigUVuWmaVuw1GDWhE6QRMA8xDTALBgNVBAMMBFJvb3SCAQEwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAgQwBQYDK2VwA0EAtiwlwNcDSKrd
ZjEMJaCBw6S5JfNOfC3PEIqdTe3Khfb6AWG+lorxLCzct9X/dCRxi6XALe0yRjHN
G6rf7fO2CQ==
-----END Certificate-----

End entity certificate:
-----BEGIN Certificate-----
MIIBUzCCAQWgAwIBAgIBAjAFBgMrZXAwDzENMAsGA1UEAwwEUm9vdDAeFw0yMjAy
MTAwNDU2MTBaFw0yMjAyMjAwNDU2MTBaMBcxFTATBgNVBAMMDEludGVybWVkaWF0
ZTAqMAUGAytlcAMhAIyY0AMf4JElyRO6flvl9y+yv+6V0Vdf76rNvQxxN6E8o34w
fDAdBgNVHQ4EFgQUu3fA9rdpTulUskoB8nskWdVLwWcwNwYDVR0jBDAwLoAUxwsL
wVA43JNXigUVuWmaVuw1GDWhE6QRMA8xDTALBgNVBAMMBFJvb3SCAQEwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAgQwBQYDK2VwA0EAtiwlwNcDSKrd
ZjEMJaCBw6S5JfNOfC3PEIqdTe3Khfb6AWG+lorxLCzct9X/dCRxi6XALe0yRjHN
G6rf7fO2CQ==
-----END Certificate-----

2022-02-09 20:56:11 INFO Certificate path is valid
PKIXCertPathValidatorResult: [
Trust Anchor: [
Trusted CA cert:   [0]         Version: 3
SerialNumber: 1
IssuerDN: CN=Root
Start Date: Wed Feb 09 20:56:10 PST 2022
Final Date: Sat Feb 19 20:56:10 PST 2022
SubjectDN: CN=Root
Public Key: Ed25519 Public Key [cf:d4:0d:9c:0d:09:39:00:6c:fd:13:a4:2e:54:ce:20:bf:10:99:4f]
public data: aa018c032378fe4f09a24ad7516755f5b9c8cb3171855479ce81f6ac5cf01b2a

Signature Algorithm: Ed25519
Signature: 06a62fbcb3c159041d3650f125e90bd3e8822016
b2459e18b460d667aef0412397367f9f3764312a
2e12bffddef1612e789353dd32b75d5d5ecb193f
4bae8b04
Extensions:
critical(false) 2.5.29.14 value = DER Octet String[20]

                       critical(false) 2.5.29.35 value = Sequence
    Tagged [0] IMPLICIT 
        DER Octet String[20] 

                       critical(true) BasicConstraints: isCa(true), pathLenConstraint = 1
                       critical(true) KeyUsage: 0x4


Policy Tree: null
Subject Public Key: Ed25519 Public Key [13:02:cb:5a:80:6a:00:a7:38:b4:c3:1b:95:7e:96:e5:cb:2a:7f:f6]
public data: a0c0c23c3d187157e88c4e063e4b64f5f0648efc4f33aee52876d271b4197382

]

```
