package com.funbasetools.security.jwt.codecs;

import com.funbasetools.security.jwt.DecodedJwt;
import com.funbasetools.security.jwt.Jwt;
import com.funbasetools.security.jwt.JwtUtils;
import com.funbasetools.security.jwt.subtypes.Header;
import com.funbasetools.security.jwt.subtypes.HeaderImpl;
import com.funbasetools.security.jwt.subtypes.Payload;
import com.funbasetools.security.jwt.subtypes.PayloadImpl;
import java.util.Map;
import java.util.function.Function;

public class JwtDecoderImpl implements JwtDecoder<Jwt> {

    private final Function<String, Map<String, Object>> jsonParser;
    private final Function<Object, Object> jsonObjectMapper;

    public JwtDecoderImpl(final Function<String, Map<String, Object>> jsonParser,
                          final Function<Object, Object> jsonObjectMapper) {
        this.jsonParser = jsonParser;
        this.jsonObjectMapper = jsonObjectMapper;
    }

    @Override
    public DecodedJwt decode(Jwt jwt) {
        return decode(jwt.getHeaderBase64(), jwt.getPayloadBase64(), jwt.getSignatureBase64());
    }

    public DecodedJwt decode(final String headerJson,
                             final String payloadJson,
                             final String signatureBase64) {

        final Map<String, Object> headerJsonObj = jsonParser.apply(headerJson);
        final Map<String, Object> payloadJsonObj = jsonParser.apply(payloadJson);

        return decode(headerJsonObj, payloadJsonObj, signatureBase64);
    }

    public DecodedJwt decode(final Map<String, Object> headerMap,
                             final Map<String, Object> payloadMap,
                             final String signatureBase64) {

        final Header header = HeaderImpl.of(JwtUtils.getClaimsFrom(headerMap, jsonObjectMapper));
        final Payload payload = PayloadImpl.of(JwtUtils.getClaimsFrom(payloadMap, jsonObjectMapper));

        return DecodedJwt.of(header, payload, signatureBase64);
    }
}
