package com.funbasetools.security.jwt.codecs;

import static com.funbasetools.security.jwt.Jwt.SEPARATOR;

import com.funbasetools.codecs.text.Base64Decoder;
import com.funbasetools.security.jwt.DecodedJwt;
import java.util.Map;
import java.util.function.Function;

public final class JwtBase64Decoder implements JwtDecoder<String> {

    private final Function<String, Map<String, Object>> jsonParser;
    private final Function<Object, Object> jsonObjectMapper;

    public JwtBase64Decoder(final Function<String, Map<String, Object>> jsonParser,
                            final Function<Object, Object> jsonObjectMapper) {
        this.jsonParser = jsonParser;
        this.jsonObjectMapper = jsonObjectMapper;
    }

    @Override
    public DecodedJwt decode(final String jwtBase64) {

        final String[] sections = jwtBase64.split("\\" + SEPARATOR);
        if (sections.length != 3) {
            throw new IllegalArgumentException("Bad JWT base64 format");
        }

        final String headerBase64 = sections[0];
        final String payloadBase64 = sections[1];
        final String signatureBase64 = sections[2];

        return decode(headerBase64, payloadBase64, signatureBase64);
    }

    public DecodedJwt decode(final String headerBase64,
                             final String payloadBase64,
                             final String signatureBase64) {

        final JwtBinaryDecoder binaryDecoder = new JwtBinaryDecoder(jsonParser, jsonObjectMapper);

        final byte[] header = Base64Decoder.URL.decode(headerBase64);
        final byte[] payload = Base64Decoder.URL.decode(payloadBase64);

        return binaryDecoder.decode(header, payload, signatureBase64);
    }
}
