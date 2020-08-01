package com.funbasetools.security.jwt.codecs;

import com.funbasetools.Function;
import com.funbasetools.security.jwt.DecodedJwt;
import com.funbasetools.security.jwt.Jwt;
import com.funbasetools.security.jwt.JwtUtils;
import com.funbasetools.security.jwt.subtypes.Section;
import java.util.Map;

public class JwtEncoderImpl implements JwtEncoder {

    private final Function<Map<String, Object>, String> jsonEncoder;

    public JwtEncoderImpl(final Function<Map<String, Object>, String> jsonEncoder) {
        this.jsonEncoder = jsonEncoder;
    }

    @Override
    public Jwt encode(DecodedJwt decodedJwt) {

        final var sectionToBase64 = Function
            .of(Section::getClaims)
            .andThen(JwtUtils::getMapFrom)
            .andThen(map -> JwtUtils.getSectionBase64(jsonEncoder, map));

        return Jwt.of(
            sectionToBase64.apply(decodedJwt.getHeader()),
            sectionToBase64.apply(decodedJwt.getPayload()),
            decodedJwt.getSignature()
        );
    }
}
