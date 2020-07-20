package com.funbasetools.security.jwt.subtypes;

import java.util.Map;
import java.util.Optional;

public abstract class SectionBase implements Section {

    private final Map<String, Claim> claims;

    protected SectionBase(final Map<String, Claim> claims) {
        this.claims = claims;
    }

    public Claim getClaim(final String name) {
        return Optional
            .ofNullable(claims.getOrDefault(name, null))
            .orElseGet(Claim::nullClaim);
    }

    public String getClaimStringOrEmpty(final String name) {
        return Optional
            .ofNullable(getClaim(name).asString())
            .orElse("");
    }

    public Map<String, Claim> getClaims() {
        return claims;
    }
}
