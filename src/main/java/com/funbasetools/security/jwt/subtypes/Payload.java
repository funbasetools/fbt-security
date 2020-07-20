package com.funbasetools.security.jwt.subtypes;

import java.time.LocalDateTime;
import java.util.List;

public interface Payload extends Section {

    List<String> getAudience();

    LocalDateTime getExpiresAt();

    String getId();

    String getIssuer();

    String getSubject();
}
