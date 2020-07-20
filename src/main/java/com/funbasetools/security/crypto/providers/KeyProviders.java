package com.funbasetools.security.crypto.providers;

import com.funbasetools.Try;
import com.funbasetools.security.crypto.PemKeyType;
import com.funbasetools.security.crypto.util.PemUtils;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class KeyProviders {

    public static RSAKeyProvider getRSAKeyProvider(
        final RSAPrivateKey privateKey,
        final RSAPublicKey publicKey) {

        return new RSAKeyProvider() {
            @Override
            public Try<RSAPrivateKey> getPrivateKey() {
                return Try.success(privateKey);
            }

            @Override
            public Try<RSAPublicKey> getPublicKey() {
                return Try.success(publicKey);
            }
        };
    }

    public static ECDSAKeyProvider getECDSAKeyProvider(
        final ECPrivateKey privateKey,
        final ECPublicKey publicKey) {

        return new ECDSAKeyProvider() {
            @Override
            public Try<ECPrivateKey> getPrivateKey() {
                return Try.success(privateKey);
            }

            @Override
            public Try<ECPublicKey> getPublicKey() {
                return Try.success(publicKey);
            }
        };
    }

    public static PrivateKey getPrivateKey(final String algorithmName, final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        final byte[] privateKeyContent = PemUtils.readPemObjectFrom(inputStream).getContent();
        final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
        final EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyContent);

        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey getPublicKey(final String algorithmName, final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        final byte[] publicKeyContent = PemUtils.readPemObjectFrom(inputStream).getContent();
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

    private KeyProviders() {
    }
}
