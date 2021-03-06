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
        if (name != null) {
            if (value == null) {
                headerMap.remove(name);
            }
            else {
                headerMap.put(name, value);
            }
        }
        return this;
    }

    public JwtBuilder ensureHeader(final String name, final Object value) {
        if (name != null && value != null) {
            if (!headerMap.containsKey(name)) {
                headerMap.put(name, value);
            }
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

    public DecodedJwt build(final Function<Map<String, Object>, String> jsonEncoder) {
        ensureHeader(TYPE_CLAIM, "JWT");

        final Header header = HeaderImpl.of(JwtUtils.getClaimsFrom(headerMap));
        final Payload payload = PayloadImpl.of(JwtUtils.getClaimsFrom(payloadMap));

        return DecodedJwt.of(header, payload, "");
    }

    public DecodedJwt buildAndSign(final JwtSigner signer) {

        final SignatureAlgorithm signatureAlgorithm = signer.getSignatureAlgorithm();

        final String algorithmId = SignatureAlgorithms
            .getAlgorithmId(signatureAlgorithm)
            .orElseThrow(() -> new IllegalArgumentException(
                String.format("Algorithm '%s' not supported", signatureAlgorithm.getName()))
            );

        addHeader(ALGORITHM_CLAIM, algorithmId);
        addHeader(TYPE_CLAIM, "JWT");

        final Header header = HeaderImpl.of(JwtUtils.getClaimsFrom(headerMap));
        final Payload payload = PayloadImpl.of(JwtUtils.getClaimsFrom(payloadMap));

        final DecodedJwt unsignedJwt = DecodedJwt.of(header, payload, null);

        return signer.sign(unsignedJwt);
    }
}
