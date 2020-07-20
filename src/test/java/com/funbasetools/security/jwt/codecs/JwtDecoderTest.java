package com.funbasetools.security.jwt.codecs;

import static com.funbasetools.security.TestHelper.jsonObjectMapper;
import static com.funbasetools.security.TestHelper.jsonParser;
import static com.funbasetools.security.jwt.subtypes.Claim.ISSUED_AT_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.NAME_CLAIM;
import static org.junit.Assert.assertEquals;

import com.funbasetools.security.jwt.DecodedJwt;
import org.junit.Test;

public class JwtDecoderTest {

    @Test
    public void testDecodeFromBase64() {
        // given
        final String jwtBase64 =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            "." +
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
            "." +
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        final JwtBase64Decoder jwtDecoder = new JwtBase64Decoder(jsonParser(), jsonObjectMapper());

        // when
        final DecodedJwt decodedJwt = jwtDecoder.decode(jwtBase64);

        // then
        assertEquals("HS256", decodedJwt.getHeader().getAlgorithm());
        assertEquals("JWT", decodedJwt.getHeader().getType());

        assertEquals("1234567890", decodedJwt.getPayload().getSubject());
        assertEquals("John Doe", decodedJwt.getPayload().getClaim(NAME_CLAIM).asString());
        assertEquals(1516239022, decodedJwt.getPayload().getClaim(ISSUED_AT_CLAIM).asInt());

        assertEquals("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", decodedJwt.getSignature());
    }
}
