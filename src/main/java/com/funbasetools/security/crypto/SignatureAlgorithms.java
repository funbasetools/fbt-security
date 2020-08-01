package com.funbasetools.security.crypto;

import com.funbasetools.ShouldNotReachThisPointException;
import com.funbasetools.io.IOUtils;
import com.funbasetools.pm.Match;
import com.funbasetools.security.SecurityUtils;
import com.funbasetools.security.crypto.providers.ECDSAKeyProvider;
import com.funbasetools.security.crypto.providers.KeyProvider;
import com.funbasetools.security.crypto.providers.RSAKeyProvider;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class SignatureAlgorithms {

    public static final String HS1_ID = "HS1";
    public static final String HS1_NAME = "HmacSHA1";
    public static final String HS224_ID = "HS224";
    public static final String HS224_NAME = "HmacSHA224";
    public static final String HS256_ID = "HS256";
    public static final String HS256_NAME = "HmacSHA256";
    public static final String HS384_ID = "HS384";
    public static final String HS384_NAME = "HmacSHA384";
    public static final String HS512_ID = "HS512";
    public static final String HS512_NAME = "HmacSHA512";
    public static final String ES224_ID = "ES224";
    public static final String ES224_NAME = "SHA224withECDSA";
    public static final String ES256_ID = "ES256";
    public static final String ES256_NAME = "SHA256withECDSA";
    public static final String ES384_ID = "ES384";
    public static final String ES384_NAME = "SHA384withECDSA";
    public static final String ES512_ID = "ES512";
    public static final String ES512_NAME = "SHA512withECDSA";
    public static final String RS1_ID = "RS1";
    public static final String RS1_NAME = "SHA1withRSA";
    public static final String RS224_ID = "RS224";
    public static final String RS224_NAME = "SHA224withRSA";
    public static final String RS256_ID = "RS256";
    public static final String RS256_NAME = "SHA256withRSA";
    public static final String RS384_ID = "RS384";
    public static final String RS384_NAME = "SHA384withRSA";
    public static final String RS512_ID = "RS512";
    public static final String RS512_NAME = "SHA512withRSA";

    public static Optional<String> getAlgorithmId(final SignatureAlgorithm algorithm) {
        return getAlgorithmId(algorithm.getName());
    }

    public static Optional<String> getAlgorithmId(final String algorithmName) {
        switch (algorithmName) {
            case RS1_NAME:
                return Optional.of(RS1_ID);
            case RS224_NAME:
                return Optional.of(RS224_ID);
            case RS256_NAME:
                return Optional.of(RS256_ID);
            case RS384_NAME:
                return Optional.of(RS384_ID);
            case RS512_NAME:
                return Optional.of(RS512_ID);
            case HS1_NAME:
                return Optional.of(HS1_ID);
            case HS224_NAME:
                return Optional.of(HS224_ID);
            case HS256_NAME:
                return Optional.of(HS256_ID);
            case HS384_NAME:
                return Optional.of(HS384_ID);
            case HS512_NAME:
                return Optional.of(HS512_ID);
            case ES224_NAME:
                return Optional.of(ES224_ID);
            case ES256_NAME:
                return Optional.of(ES256_ID);
            case ES384_NAME:
                return Optional.of(ES384_ID);
            case ES512_NAME:
                return Optional.of(ES512_ID);

            default:
                return Optional.empty();
        }
    }

    public static Optional<SignatureAlgorithm> getAlgorithmProviderById(final String algorithmId,
                                                                        final Object keyProvider) {
        return Match
            .<SignatureAlgorithm>when(algorithmId, keyProvider)
            .isTuple(RS512_ID, RSAKeyProvider.class).then(SignatureAlgorithms::getSha512WithRsa)
            .isTuple(ES512_ID, ECDSAKeyProvider.class).then(SignatureAlgorithms::getSha224WithEcdsa)
            .isTuple(HS512_ID, byte[].class).then(SignatureAlgorithms::getHmacSha512)
            .isTuple(RS384_ID, RSAKeyProvider.class).then(SignatureAlgorithms::getSha384WithRsa)
            .isTuple(ES384_ID, ECDSAKeyProvider.class).then(SignatureAlgorithms::getSha224WithEcdsa)
            .isTuple(HS384_ID, byte[].class).then(SignatureAlgorithms::getHmacSha384)
            .isTuple(RS256_ID, RSAKeyProvider.class).then(SignatureAlgorithms::getSha256WithRsa)
            .isTuple(ES256_ID, ECDSAKeyProvider.class).then(SignatureAlgorithms::getSha224WithEcdsa)
            .isTuple(HS256_ID, byte[].class).then(SignatureAlgorithms::getHmacSha256)
            .isTuple(RS224_ID, RSAKeyProvider.class).then(SignatureAlgorithms::getSha224WithRsa)
            .isTuple(ES224_ID, ECDSAKeyProvider.class).then(SignatureAlgorithms::getSha224WithEcdsa)
            .isTuple(HS224_ID, byte[].class).then(SignatureAlgorithms::getHmacSha224)
            .isTuple(RS1_ID,   RSAKeyProvider.class).then(SignatureAlgorithms::getSha1WithRsa)
            .isTuple(HS1_ID,   byte[].class).then(SignatureAlgorithms::getHmacSha1)
            .toOptional();
    }

    public static SignatureAlgorithm getSha224WithEcdsa(final ECDSAKeyProvider ECDSAKeyProvider) {
        return fromSignature(ES224_NAME, ECDSAKeyProvider);
    }

    public static SignatureAlgorithm getSha256WithEcdsa(final ECDSAKeyProvider ECDSAKeyProvider) {
        return fromSignature(ES256_NAME, ECDSAKeyProvider);
    }

    public static SignatureAlgorithm getSha384WithEcdsa(final ECDSAKeyProvider ECDSAKeyProvider) {
        return fromSignature(ES384_NAME, ECDSAKeyProvider);
    }

    public static SignatureAlgorithm getSha512WithEcdsa(final ECDSAKeyProvider ECDSAKeyProvider) {
        return fromSignature(ES512_NAME, ECDSAKeyProvider);
    }

    public static SignatureAlgorithm getHmacSha1(final byte[] secret) {
        return fromMac(HS1_NAME, secret);
    }

    public static SignatureAlgorithm getHmacSha224(final byte[] secret) {
        return fromMac(HS224_NAME, secret);
    }

    public static SignatureAlgorithm getHmacSha256(final byte[] secret) {
        return fromMac(HS256_NAME, secret);
    }

    public static SignatureAlgorithm getHmacSha384(final byte[] secret) {
        return fromMac(HS384_NAME, secret);
    }

    public static SignatureAlgorithm getHmacSha512(final byte[] secret) {
        return fromMac(HS512_NAME, secret);
    }

    public static SignatureAlgorithm getSha1WithRsa(final RSAKeyProvider rsaKeyProvider) {
        return fromSignature(RS1_NAME, rsaKeyProvider);
    }

    public static SignatureAlgorithm getSha224WithRsa(final RSAKeyProvider rsaKeyProvider) {
        return fromSignature(RS224_NAME, rsaKeyProvider);
    }

    public static SignatureAlgorithm getSha256WithRsa(final RSAKeyProvider rsaKeyProvider) {
        return fromSignature(RS256_NAME, rsaKeyProvider);
    }

    public static SignatureAlgorithm getSha384WithRsa(final RSAKeyProvider rsaKeyProvider) {
        return fromSignature(RS384_NAME, rsaKeyProvider);
    }

    public static SignatureAlgorithm getSha512WithRsa(final RSAKeyProvider rsaKeyProvider) {
        return fromSignature(RS512_NAME, rsaKeyProvider);
    }

    public static SignatureAlgorithm fromMac(final String algorithmName, final byte[] secret) {
        return SecurityUtils.securityAlgorithmFromNameFunc(
            Mac::getInstance,
            mac -> new SignatureAlgorithm() {

                @Override
                public byte[] sign(final InputStream content)
                    throws IOException, GeneralSecurityException {

                    final SecretKeySpec secretKeySpec = new SecretKeySpec(secret, mac.getAlgorithm());
                    mac.init(secretKeySpec);

                    IOUtils.readAllBytesWithBuffer(
                        content,
                        (buffer, read) -> mac.update(buffer, 0, read)
                    );

                    return mac.doFinal();
                }

                @Override
                public String getName() {
                    return mac.getAlgorithm();
                }
            },
            algorithmName
        );
    }

    public static <PVK extends PrivateKey, PUK extends PublicKey> SignatureAlgorithm fromSignature(
        final String algorithmName,
        final KeyProvider<PVK, PUK> rsaKeyProvider) {

        return SecurityUtils.securityAlgorithmFromNameFunc(
            Signature::getInstance,
            signatureAlg -> new SignatureAlgorithm() {
                @Override
                public byte[] sign(InputStream content) throws IOException, GeneralSecurityException {
                    return rsaKeyProvider.getPrivateKey()
                        .map(pvk -> {
                            signatureAlg.initSign(pvk);
                            IOUtils.readAllBytesWithBuffer(
                                content,
                                (buffer, read) -> signatureAlg.update(buffer, 0, read)
                            );
                            return signatureAlg.sign();
                        })
                        .throwIfFailureWith(IOException.class)
                        .throwIfFailureWith(GeneralSecurityException.class)
                        .toOptional()
                        .orElseThrow(ShouldNotReachThisPointException::new);
                }

                @Override
                public boolean verify(InputStream content, byte[] signature) {
                    final byte[] safeSignature = Optional
                        .ofNullable(signature)
                        .orElseGet(() -> new byte[0]);

                    return rsaKeyProvider.getPublicKey()
                        .map(puk -> {
                            signatureAlg.initVerify(puk);
                            IOUtils.readAllBytesWithBuffer(
                                content,
                                (buffer, read) -> signatureAlg.update(buffer, 0, read)
                            );
                            return signatureAlg.verify(signature);
                        })
                        .toOptional()
                        .orElseThrow(ShouldNotReachThisPointException::new);
                }

                @Override
                public String getName() {
                    return signatureAlg.getAlgorithm();
                }
            },
            algorithmName);
    }

    private SignatureAlgorithms() {
    }
}
