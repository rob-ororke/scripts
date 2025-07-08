//DEPS org.bouncycastle:bcpkix-jdk18on:1.78.1
public class GenKeys {
    // TODO UPDATE THIS CONSTANT WITH THE NAME OF YOUR APP, e.g. DigitalSignage
    private static final String APP_NAME = "CHANGE_ME";
    // --- Configuration ---
    // The algorithm for the key pair generation
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    // The password for the PFX (PKCS#12) file
    private static final char[] PFX_PASSWORD = createPassword().toCharArray();
    // Output filenames
    private static final String PRIVATE_KEY_AND_CERT_PFX_FILE = APP_NAME + "_private_key.pfx";
    // Common Name (CN) for the self-signed certificate
    private static final X500Name CERTIFICATE_NAME = new X500Name("CN=" + APP_NAME);
    private static final String CERT_FILE = APP_NAME + "_certificate.cer";
    public static void main(String... args) throws Exception {
        // 1. Add the Bouncy Castle security provider
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        // 2. Generate an Elliptic Curve key pair
        System.out.println("🔄 Generating EC key pair...");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, bcProvider);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        System.out.println("✅ Private key generated successfully.");
        // 3. Create a self-signed certificate
        System.out.println("📜 Creating a self-signed certificate...");
        X509Certificate certificate = createSelfSignedCertificate(keyPair);
        System.out.println("✅ Self-signed certificate created.");
        // 4. Export the private key and certificate to a PFX file
        System.out.printf("🔐 Exporting private key and certificate to %s...%n", PRIVATE_KEY_AND_CERT_PFX_FILE);
        exportToPfx(keyPair, certificate);
        System.out.println("✅ Private key and certificate exported successfully.");
        // 5. Export the public key to a PEM file
        System.out.printf("🔑 Exporting public key to %s...%n", CERT_FILE);
        exportCertToFile(certificate);
        System.out.println("✅ Public key exported successfully.");
        System.out.printf("✅ Password for PFX file %s %n", new String(PFX_PASSWORD));
        System.out.println("\n✨ All operations completed!");
    }
    private static X509Certificate createSelfSignedCertificate(KeyPair keyPair) throws Exception {
        Instant now = Instant.now();
        Date validFrom = Date.from(now);
        Date validTo = Date.from(now.plus(365, ChronoUnit.DAYS));
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                CERTIFICATE_NAME,
            BigInteger.valueOf(System.currentTimeMillis()), // Serial Number
            validFrom, // Not Before
            validTo, // Not After
            CERTIFICATE_NAME, // Subject
            subPubKeyInfo // Public Key
        );
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(certBuilder.build(contentSigner));
    }
    private static void exportToPfx(KeyPair keyPair, X509Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(null, null); // Initialize a new keystore
        keyStore.setKeyEntry(
            "My Cool Company Key", // Alias for the key
            keyPair.getPrivate(), 
            PFX_PASSWORD, // Password to protect the key
            new X509Certificate[]{certificate} // Certificate chain
        );
        try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_AND_CERT_PFX_FILE)) {
            keyStore.store(fos, PFX_PASSWORD); // Password to protect the entire keystore
        }
    }
    private static String createPassword() {
        byte[] b = new byte[32];
        new Random().nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }
    private static void exportCertToFile(X509Certificate cert) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(CERT_FILE)) {
            fos.write(cert.getEncoded());
        }
    }
}
