package com.funbasetools.security.jwt.subtypes;

public interface Header extends Section {

    String getAlgorithm();

    String getContentType();

    String getKeyId();

    String getType();
}
