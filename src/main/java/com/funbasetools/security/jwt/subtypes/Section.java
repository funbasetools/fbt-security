package com.funbasetools.security.jwt.subtypes;

import java.util.Map;

public interface Section {

    Claim getClaim(final String name);

    Map<String, Claim> getClaims();
}
