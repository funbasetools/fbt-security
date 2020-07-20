package com.funbasetools.security.jwt.codecs;

import static com.funbasetools.security.jwt.Jwt.JWT_CHARSET;
import static com.funbasetools.security.jwt.Jwt.SEPARATOR;

import com.funbasetools.BytesUtil;
import com.funbasetools.codecs.text.Base64Encoder;
import com.funbasetools.security.jwt.DecodedJwt;
import java.util.Map;
import java.util.function.Function;

public class JwtBinaryDecoder implements JwtDecoder<byte[]> {

    private final Function<String, Map<String, Object>> jsonParser;
    private final Function<Object, Object> jsonObjectMapper;

    public JwtBinaryDecoder(final Function<String, Map<String, Object>> jsonParser,
                            final Function<Object, Object> jsonObjectMapper) {
        this.jsonParser = jsonParser;
        this.jsonObjectMapper = jsonObjectMapper;
    }

    @Override
    public DecodedJwt decode(final byte[] jwtBytes) {
        final byte separator = (byte) SEPARATOR;

        int firstIndex = BytesUtil.indexOf(separator, jwtBytes);
        int secondIndex = firstIndex > 0
            ? BytesUtil.indexOf(separator, jwtBytes, firstIndex + 1)
            : -1;

        if (firstIndex <= 0 || secondIndex <= firstIndex) {
            throw new IllegalArgumentException("Bad JWT bytes format");
        }

        final byte[] header = new byte[firstIndex];
        final byte[] payload = new byte[secondIndex - firstIndex - 1];
        final byte[] signature = new byte[jwtBytes.length - secondIndex - 1];

        System.arraycopy(jwtBytes, 0, header, 0, header.length);
        System.arraycopy(jwtBytes, firstIndex + 1, payload, 0, payload.length);
        System.arraycopy(jwtBytes, secondIndex + 1, signature, 0, signature.length);

        return decode(header, payload, signature);
    }

    public DecodedJwt decode(final byte[] header,
                             final byte[] payload,
                             final byte[] signature) {

        return decode(header, payload, Base64Encoder.URL.encode(signature));
    }

    public DecodedJwt decode(final byte[] header,
                             final byte[] payload,
                             final String signatureBase64) {

        final String headerJson = new String(header, JWT_CHARSET);
        final String payloadJson = new String(payload, JWT_CHARSET);

        final var jsonDecoder = new JwtDecoderImpl(jsonParser, jsonObjectMapper);

        return jsonDecoder.decode(headerJson, payloadJson, signatureBase64);
    }
}
