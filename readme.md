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

    PKIXCertPathValidatorResult: [
    Trust Anchor: [
    Trusted CA cert:   [0]         Version: 3
    SerialNumber: 1
    IssuerDN: CN=Root
    Start Date: Sat Sep 04 12:53:44 PDT 2021
    Final Date: Tue Sep 14 12:53:44 PDT 2021
    SubjectDN: CN=Root
    Public Key: Ed25519 Public Key [11:77:cf:a5:8f:9d:16:0a:f9:62:1d:ed:6f:6d:21:a2:6a:f9:8b:bf]
    public data: 7f738f5de1eaa76cfa14dd238420d3810a472547a4510112306d85ed32dffe21
    
    Signature Algorithm: Ed25519
    Signature: 0539982edd548ef5d5e90462841147ab33b31e37
    79af07f8855fdb81cee3fb917dd015c49e067839
    4910819b09e6ebeecc75253bb0cce13caaf76fef
    1e66280a
    Extensions:
    critical(false) 2.5.29.14 value = DER Octet String[20]
    
                       critical(false) 2.5.29.35 value = Sequence
    Tagged [0] IMPLICIT 
        DER Octet String[20] 
    
                       critical(true) BasicConstraints: isCa(true), pathLenConstraint = 1
                       critical(true) KeyUsage: 0x4
    
    
    Policy Tree: null
    Subject Public Key: Ed25519 Public Key [d0:00:ae:1e:18:11:c0:04:45:3b:fc:ea:ed:82:29:b5:6d:bf:31:58]
    public data: cb32bc357f4835a19e274b9f777b9efa99cf1a1866fe95f4b91afc528b26ea4c
    
    ]

