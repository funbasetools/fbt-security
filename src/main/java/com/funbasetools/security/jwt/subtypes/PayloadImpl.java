package com.funbasetools.security.jwt.subtypes;

import static com.funbasetools.security.jwt.subtypes.Claim.AUDIENCE_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.EXPIRATION_TIME_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.ISSUER_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.JWT_ID_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.SUBJECT_CLAIM;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class PayloadImpl
    extends SectionBase implements Payload {

    public static PayloadImpl of(final Map<String, Claim> claims) {
        return new PayloadImpl(claims);
    }

    private PayloadImpl(Map<String, Claim> claims) {
        super(claims);
    }

    @Override
    public List<String> getAudience() {
        return getClaim(AUDIENCE_CLAIM).asListOf(String.class);
    }

    @Override
    public LocalDateTime getExpiresAt() {
        return getClaim(EXPIRATION_TIME_CLAIM).asDateTime();
    }

    @Override
    public String getId() {
        return getClaimStringOrEmpty(JWT_ID_CLAIM);
    }

    @Override
    public String getIssuer() {
        return getClaimStringOrEmpty(ISSUER_CLAIM);
    }

    @Override
    public String getSubject() {
        return getClaimStringOrEmpty(SUBJECT_CLAIM);
    }
}
