package com.funbasetools.security.jwt.codecs;

import com.funbasetools.codecs.Decoder;
import com.funbasetools.security.jwt.DecodedJwt;

public interface JwtDecoder<SOURCE> extends Decoder<SOURCE, DecodedJwt> {
}
