package com.funbasetools.security.jwt;

import com.funbasetools.codecs.text.Base64Decoder;
import com.funbasetools.security.crypto.SignatureAlgorithm;
import java.util.Map;
import java.util.function.Function;

public class JwtVerifier {

    private final Function<Map<String, Object>, String> jsonEncoder;

    public JwtVerifier(final Function<Map<String, Object>, String> jsonEncoder) {
        this.jsonEncoder = jsonEncoder;
    }

    public boolean verify(final DecodedJwt decodedJwt, final SignatureAlgorithm signatureAlgorithm) {
        final byte[] jwtContent = decodedJwt.getContentBytes(jsonEncoder);
        final byte[] signature = Base64Decoder.URL.decode(decodedJwt.getSignature());

        return signatureAlgorithm.verify(jwtContent, signature);
    }
}
