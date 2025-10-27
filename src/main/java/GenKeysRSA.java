///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.bouncycastle:bcpkix-jdk18on:1.78.1

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class GenKeysRSA {
  // --- Configuration ---
  private static final String KEY_ALGORITHM = "RSA";
  private static final int KEY_SIZE = 2048;
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
  private static final char[] PFX_PASSWORD = createPassword().toCharArray();
  private static String appName;

  public static void main(String... args) throws Exception {
    if (args.length != 1) {
      System.err.println("Please provide 1 argument, the application name");
      System.exit(1);
    }
    if (args[0] == null || args[0].trim().isEmpty()) {
      System.err.println("Please provide 1 non-empty argument, the application name");
      System.exit(2);
    }

    appName = args[0];

    Provider bcProvider = new BouncyCastleProvider();
    Security.addProvider(bcProvider);

    System.out.println("🔄 Generating RSA key pair...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, bcProvider);
    keyPairGenerator.initialize(KEY_SIZE);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    System.out.println("✅ Private key generated successfully.");

    System.out.println("📜 Creating a self-signed certificate (RSA)...");
    X509Certificate certificate = createSelfSignedCertificate(keyPair);
    System.out.println("✅ Self-signed certificate created.");

    System.out.printf("🔐 Exporting private key and certificate to %s...%n", getPrivateKeyAndCertPfxFile());
    exportToPfx(keyPair, certificate);
    System.out.println("✅ Private key and certificate exported successfully.");

    System.out.printf("🔑 Exporting public key to %s...%n", getPublicKeyPemFile());
    exportToPem(keyPair);
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
            getCertificateName(),
            BigInteger.valueOf(System.currentTimeMillis()),
            validFrom,
            validTo,
            getCertificateName(),
            subPubKeyInfo
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
    keyStore.load(null, null);

    keyStore.setKeyEntry(
            "My Cool Company Key",
            keyPair.getPrivate(),
            PFX_PASSWORD,
            new X509Certificate[]{certificate}
    );

    try (FileOutputStream fos = new FileOutputStream(getPrivateKeyAndCertPfxFile())) {
      keyStore.store(fos, PFX_PASSWORD);
    }
  }

  private static void exportToPem(KeyPair keyPair) throws IOException {
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(getPublicKeyPemFile()))) {
      pemWriter.writeObject(keyPair.getPublic());
    }
  }

  private static String createPassword() {
    byte[] b = new byte[32];
    new SecureRandom().nextBytes(b);
    return Base64.getEncoder().encodeToString(b);
  }

  private static String getPrivateKeyAndCertPfxFile() {
    return appName + "_private_key.pfx";
  }

  private static String getPublicKeyPemFile() {
    return appName + "_public_key.pem";
  }

  private static X500Name getCertificateName() {
    return new X500Name("CN=" + appName);
  }
}
