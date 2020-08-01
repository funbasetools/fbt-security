package com.funbasetools.security.jwt.codecs;

import com.funbasetools.codecs.Encoder;
import com.funbasetools.security.jwt.DecodedJwt;
import com.funbasetools.security.jwt.Jwt;

public interface JwtEncoder extends Encoder<DecodedJwt, Jwt> {
}
