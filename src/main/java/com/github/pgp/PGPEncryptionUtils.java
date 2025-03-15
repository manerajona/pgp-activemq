package com.github.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

public class PGPEncryptionUtils {

    static {
        // Register Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    private PGPEncryptionUtils() {
    }

    public static byte[] encrypt(byte[] data, PGPPublicKey publicKey, boolean withIntegrityCheck, boolean armor) throws IOException, PGPException {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        // Compress the data
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream cos = comData.open(bOut);

        // Write literal data (the actual message)
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
        pOut.write(data);
        pOut.close();
        comData.close();

        byte[] bytes = bOut.toByteArray();

        // Set up the encryption generator
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(BouncyCastleProvider.PROVIDER_NAME));

        OutputStream cOut = encGen.open(out, bytes.length);
        cOut.write(bytes);
        cOut.close();
        if (armor) {
            out.close();
        }
        return encOut.toByteArray();
    }

    public static String decrypt(byte[] encryptedData, PGPSecretKeyRingCollection pgpSec, char[] passphrase) throws IOException, PGPException {
        InputStream in = new ByteArrayInputStream(encryptedData);
        PGPObjectFactory pgpF =
                new PGPObjectFactory(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList enc = switch (pgpF.nextObject()) {
            case PGPEncryptedDataList pgpEncryptedData -> pgpEncryptedData;
            case null, default -> (PGPEncryptedDataList) pgpF.nextObject();
        };

        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        while (it.hasNext()) {
            Object obj = it.next();
            pbe = (PGPPublicKeyEncryptedData) obj;
            PGPSecretKey secretKey = pgpSec.getSecretKey(pbe.getKeyID());
            if (secretKey != null) {
                sKey = secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase)
                );
                break;
            }
        }
        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(sKey)
        );
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData cData) {
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
            message = pgpFact.nextObject();
        }

        if (message instanceof PGPLiteralData ld) {
            InputStream unc = ld.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
            return out.toString(StandardCharsets.UTF_8);
        } else {
            throw new PGPException("Message is not a simple encrypted file.");
        }
    }

    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException, IllegalArgumentException {
        PGPPublicKeyRingCollection pgpPub =
                new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = keyIter.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in) throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
    }
}
