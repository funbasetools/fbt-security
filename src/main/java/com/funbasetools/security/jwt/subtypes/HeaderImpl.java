package com.funbasetools.security.jwt.subtypes;

import static com.funbasetools.security.jwt.subtypes.Claim.ALGORITHM_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.CONTENT_TYPE_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.KEY_ID_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.TYPE_CLAIM;

import java.util.Map;

public class HeaderImpl
    extends SectionBase implements Header {

    private final String algorithm;
    private final String type;
    private final String contentType;
    private final String keyId;

    public static HeaderImpl of(final Map<String, Claim> claims) {
        return new HeaderImpl(claims);
    }

    private HeaderImpl(final Map<String, Claim> claims) {
        super(claims);
        algorithm = getClaimStringOrEmpty(ALGORITHM_CLAIM);
        type = getClaimStringOrEmpty(TYPE_CLAIM);
        contentType = getClaimStringOrEmpty(CONTENT_TYPE_CLAIM);
        keyId = getClaimStringOrEmpty(KEY_ID_CLAIM);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    @Override
    public String getType() {
        return type;
    }
}
