package com.funbasetools.security.jwt;

import java.util.LinkedHashMap;
import java.util.Map;

public class JwtToken {

    private final Map<String, String> header;
    private final Map<String, String> payload;
    private final Map<String, String> signature;

    private JwtToken() {
        header = new LinkedHashMap<String, String>();
        payload = new LinkedHashMap<String, String>();
        signature = new LinkedHashMap<String, String>();
    }
}
