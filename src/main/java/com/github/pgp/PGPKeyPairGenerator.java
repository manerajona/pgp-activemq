package com.github.pgp;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import static com.github.pgp.Constants.*;

public class PGPKeyPairGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Initialize the key pair generator for RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());

        // Generate key pairs for signing and encryption
        KeyPair signingKeyPair = kpg.generateKeyPair();
        KeyPair encryptionKeyPair = kpg.generateKeyPair();

        // Convert the java.security.KeyPair to an AsymmetricCipherKeyPair for the signing key
        AsymmetricKeyParameter signingPub = PublicKeyFactory.createKey(signingKeyPair.getPublic().getEncoded());
        AsymmetricKeyParameter signingPriv = PrivateKeyFactory.createKey(signingKeyPair.getPrivate().getEncoded());
        AsymmetricCipherKeyPair signingAsymKeyPair = new AsymmetricCipherKeyPair(signingPub, signingPriv);

        // Do the same for the encryption key
        AsymmetricKeyParameter encryptionPub = PublicKeyFactory.createKey(encryptionKeyPair.getPublic().getEncoded());
        AsymmetricKeyParameter encryptionPriv = PrivateKeyFactory.createKey(encryptionKeyPair.getPrivate().getEncoded());
        AsymmetricCipherKeyPair encryptionAsymKeyPair = new AsymmetricCipherKeyPair(encryptionPub, encryptionPriv);

        // Create BcPGPKeyPair instances using the AsymmetricCipherKeyPair objects
        PGPKeyPair pgpSignKeyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN, signingAsymKeyPair, new Date());
        PGPKeyPair pgpEncKeyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_ENCRYPT, encryptionAsymKeyPair, new Date());

        // Create a subpacket generator for signature metadata (optional)
        PGPSignatureSubpacketGenerator subpacketGen = new PGPSignatureSubpacketGenerator();

        // Create the key ring generator with your signing key
        char[] passphrase = PRIVATE_KEY_PASSPHRASE.toCharArray();
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, 
                pgpSignKeyPair,
                PRIVATE_KEY_IDENTITY,
                new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
                subpacketGen.generate(), 
                null,
                new JcaPGPContentSignerBuilder(
                        pgpSignKeyPair.getPublicKey().getAlgorithm(), 
                        HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, 
                        new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1))
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(passphrase)
        );

        // Add the encryption key as a subkey
        keyRingGen.addSubKey(pgpEncKeyPair);

        // Write the public key ring to a file (in ASCII-armored format)
        try (ArmoredOutputStream pubOut = new ArmoredOutputStream(new FileOutputStream(PUBLIC_KEY_FILE))) {
            keyRingGen.generatePublicKeyRing().encode(pubOut);
        }

        // Write the secret key ring to a file (in ASCII-armored format)
        try (ArmoredOutputStream secOut = new ArmoredOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
            keyRingGen.generateSecretKeyRing().encode(secOut);
        }
    }
}
