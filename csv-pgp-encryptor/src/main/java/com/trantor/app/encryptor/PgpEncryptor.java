package com.trantor.app.encryptor;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

@Component
public class PgpEncryptor {

    public void encryption(String publicKeyFilePath, String inputFilePath, String outputFilePath) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        // Load Public Key File
        FileInputStream key = new FileInputStream(publicKeyFilePath);
        PGPPublicKey pubKey = readPublicKey(key);

        System.out.println("pubKey:" + pubKey);
        System.out.println("pubKey.getAlgorithm():" + pubKey.getAlgorithm());
        System.out.println("pubKey.getBitStrength():" + pubKey.getBitStrength());
        System.out.println("pubKey.getVersion():" + pubKey.getVersion());

        // Output file
        FileOutputStream outputFile = new FileOutputStream(outputFilePath);

        // Other settings
        boolean armor = true;

        boolean integrityCheck = true;
        encryptFile(outputFile, inputFilePath, pubKey, armor, integrityCheck);
    }

    private PGPPublicKey readPublicKey(InputStream paramInputStream) throws IOException, PGPException {
        PGPPublicKeyRingCollection localPGPPublicKeyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(paramInputStream));
        Iterator localIterator1 = localPGPPublicKeyRingCollection.getKeyRings();
        while (localIterator1.hasNext()) {
            PGPPublicKeyRing localPGPPublicKeyRing = (PGPPublicKeyRing) localIterator1.next();
            Iterator localIterator2 = localPGPPublicKeyRing.getPublicKeys();
            while (localIterator2.hasNext()) {
                PGPPublicKey localPGPPublicKey = (PGPPublicKey) localIterator2.next();
                if (localPGPPublicKey.isEncryptionKey())
                    return localPGPPublicKey;
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private void encryptFile(OutputStream outputStream, String fileToEncrypt,
                             PGPPublicKey paramPGPPublicKey, boolean armor, boolean integrityCheck)
            throws IOException, NoSuchProviderException {
        if (armor)
            outputStream = new ArmoredOutputStream(outputStream);
        try {
            byte[] arrayOfByte = compressFile(fileToEncrypt);

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(SymmetricKeyAlgorithmTags.AES_256, integrityCheck, new SecureRandom(), "BC");
            encryptedDataGenerator.addMethod(paramPGPPublicKey);

            try (OutputStream localOutputStream = encryptedDataGenerator.open(outputStream, arrayOfByte.length);) {
                localOutputStream.write(arrayOfByte);
            }


            if (armor)
                outputStream.close();
        } catch (PGPException localPGPException) {
            System.err.println(localPGPException);
            if (localPGPException.getUnderlyingException() != null)
                localPGPException.getUnderlyingException().printStackTrace();
        }
    }

    private byte[] compressFile(String paramString) throws IOException {
        ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator localPGPCompressedDataGenerator = new PGPCompressedDataGenerator(1);
        PGPUtil.writeFileToLiteralData(localPGPCompressedDataGenerator.open(localByteArrayOutputStream), 'b',
                new File(paramString));
        localPGPCompressedDataGenerator.close();
        return localByteArrayOutputStream.toByteArray();
    }


}

