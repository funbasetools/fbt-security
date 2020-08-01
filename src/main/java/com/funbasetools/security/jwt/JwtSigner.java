package com.funbasetools.security.jwt;

import com.funbasetools.Try;
import com.funbasetools.codecs.text.Base64Encoder;
import com.funbasetools.security.crypto.SignatureAlgorithm;
import java.util.Map;
import java.util.function.Function;

public class JwtSigner {

    private final Function<Map<String, Object>, String> jsonEncoder;
    private final SignatureAlgorithm signatureAlgorithm;

    public JwtSigner(final Function<Map<String, Object>, String> jsonEncoder,
                     final SignatureAlgorithm signatureAlgorithm) {
        this.jsonEncoder = jsonEncoder;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public DecodedJwt sign(final DecodedJwt decodedJwt) {

        final byte[] jwtContent = decodedJwt.getContentBytes(jsonEncoder);

        final byte[] signatureBytes = Try
            .of(() -> signatureAlgorithm.sign(jwtContent))
            .toOptional()
            .orElseGet(() -> new byte[0]);

        final String signature = Base64Encoder.URL_NO_PADDING.encode(signatureBytes);

        return DecodedJwt.of(decodedJwt.getHeader(), decodedJwt.getPayload(), signature);
    }
}
