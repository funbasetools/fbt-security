package com.funbasetools.security.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public final class PemUtils {

    public static PemObject readPemObjectFrom(final InputStream inputStream) throws IOException {
        final PemReader pemReader = new PemReader(new InputStreamReader(inputStream));
        return pemReader.readPemObject();
    }

    public static PrivateKey getPrivateKey(final String algorithmName, final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        final byte[] privateKeyContent = readPemObjectFrom(inputStream).getContent();
        final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
        final EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyContent);

        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey getPublicKey(final String algorithmName, final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        final byte[] publicKeyContent = readPemObjectFrom(inputStream).getContent();
        final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
        final EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyContent);

        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey getPrivateKey(final PemKeyType keyType, final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        return getPrivateKey(keyType.name(), inputStream);
    }

    public static PublicKey getPublicKey(final PemKeyType keyType, final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        return getPublicKey(keyType.name(), inputStream);
    }

    private PemUtils() {
    }
}
