package com.funbasetools.security.jwt;

import com.funbasetools.security.jwt.subtypes.Header;
import com.funbasetools.security.jwt.subtypes.Payload;
import java.util.Map;
import java.util.function.Function;

public interface DecodedJwt {

    Header getHeader();

    Payload getPayload();

    String getSignature();

    default byte[] getContentBytes(final Function<Map<String, Object>, String> jsonEncoder) {
        return JwtUtils.getJwtContentBytes(
            JwtUtils.getMapFrom(getHeader().getClaims()),
            JwtUtils.getMapFrom(getPayload().getClaims()),
            jsonEncoder
        );
    }

    static DecodedJwt of(final Header header,
                         final Payload payload,
                         final String signature) {

        return new DecodedJwt() {
            @Override
            public Header getHeader() {
                return header;
            }

            @Override
            public Payload getPayload() {
                return payload;
            }

            @Override
            public String getSignature() {
                return signature;
            }
        };
    }
}
