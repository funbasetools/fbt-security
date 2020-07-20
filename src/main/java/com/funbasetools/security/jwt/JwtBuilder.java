package com.funbasetools.security.jwt;

import static com.funbasetools.security.jwt.subtypes.Claim.ALGORITHM_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.AUDIENCE_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.CONTENT_TYPE_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.EXPIRATION_TIME_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.ISSUER_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.JWT_ID_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.KEY_ID_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.SUBJECT_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.TYPE_CLAIM;

import com.funbasetools.Try;
import com.funbasetools.codecs.text.Base64Encoder;
import com.funbasetools.security.crypto.SignatureAlgorithm;
import com.funbasetools.security.crypto.SignatureAlgorithms;
import com.funbasetools.security.jwt.subtypes.Header;
import com.funbasetools.security.jwt.subtypes.HeaderImpl;
import com.funbasetools.security.jwt.subtypes.Payload;
import com.funbasetools.security.jwt.subtypes.PayloadImpl;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

public final class JwtBuilder {

    private final Map<String, Object> headerMap = new LinkedHashMap<>();
    private final Map<String, Object> payloadMap = new LinkedHashMap<>();

    public JwtBuilder addClaim(final String name, final Object value) {
        if (value == null) {
            payloadMap.remove(name);
        }
        else {
            payloadMap.put(name, value);
        }
        return this;
    }

    public JwtBuilder addHeader(final String name, final Object value) {
        if (value == null) {
            headerMap.remove(name);
        }
        else {
            headerMap.put(name, value);
        }
        return this;
    }

    public JwtBuilder withAudience(final String...audiences) {
        return addClaim(AUDIENCE_CLAIM, Arrays.asList(audiences));
    }

    public JwtBuilder withContentType(final String contentType) {
        return addHeader(CONTENT_TYPE_CLAIM, contentType);
    }

    public JwtBuilder withExpirationTime(final LocalDateTime expiration) {
        return addClaim(EXPIRATION_TIME_CLAIM, expiration);
    }

    public JwtBuilder withIssuer(final String issuer) {
        return addClaim(ISSUER_CLAIM, issuer);
    }

    public JwtBuilder withId(final String id) {
        return addClaim(JWT_ID_CLAIM, id);
    }

    public JwtBuilder withKeyId(final String keyId) {
        return addHeader(KEY_ID_CLAIM, keyId);
    }

    public JwtBuilder withSubject(final String subject) {
        return addClaim(SUBJECT_CLAIM, subject);
    }

    public DecodedJwt buildAndSign(final SignatureAlgorithm signatureAlgorithm,
                                   final Function<Map<String, Object>, String> jsonEncoder) {
        final String algorithmId = SignatureAlgorithms
            .getAlgorithmId(signatureAlgorithm)
            .orElseThrow(() -> new IllegalArgumentException(
                String.format("Algorithm '%s' not supported", signatureAlgorithm.getName()))
            );

        addHeader(ALGORITHM_CLAIM, algorithmId);
        addHeader(TYPE_CLAIM, "JWT");

        final Header header = HeaderImpl.of(JwtUtils.getClaimsFrom(headerMap));
        final Payload payload = PayloadImpl.of(JwtUtils.getClaimsFrom(payloadMap));

        final String signatureBase64 = sign(signatureAlgorithm, jsonEncoder);

        return DecodedJwt.of(header, payload, signatureBase64);
    }

    // private methods

    private String sign(final SignatureAlgorithm signatureAlgorithm,
                        final Function<Map<String, Object>, String> jsonEncoder) {

        final byte[] contentBytes = JwtUtils.getJwtContentBytes(headerMap, payloadMap, jsonEncoder);

        final byte[] signatureBytes = Try
            .of(() -> signatureAlgorithm.sign(contentBytes))
            .toOptional()
            .orElseGet(() -> new byte[0]);

        return Base64Encoder.URL_NO_PADDING.encode(signatureBytes);
    }
}
