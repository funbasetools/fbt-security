package com.funbasetools.security.jwt;

import com.funbasetools.BytesUtil;
import com.funbasetools.codecs.text.Base64Decoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public interface Jwt {

    Charset JWT_CHARSET = StandardCharsets.UTF_8;
    char SEPARATOR = (char)46;

    String getHeaderBase64();

    String getPayloadBase64();

    String getSignatureBase64();

    default byte[] getHeaderBytes() {
        return Base64Decoder.URL.decode(getHeaderBase64());
    }

    default byte[] getPayloadBytes() {
        return Base64Decoder.URL.decode(getPayloadBase64());
    }

    default byte[] getSignatureBytes() {
        return Base64Decoder.URL.decode(getSignatureBase64());
    }

    default String getBase64() {
        return String.format(
            "%s.%s.%s",
            getHeaderBase64(),
            getPayloadBase64(),
            getSignatureBase64()
        );
    }

    default byte[] getBytes() {
        return BytesUtil.join(
            (byte) SEPARATOR,
            getHeaderBytes(),
            getPayloadBytes(),
            getSignatureBytes()
        );
    }

    static Jwt of(final String headerBase64,
                  final String payloadBase64,
                  final String signature) {

        return new Jwt() {
            @Override
            public String getHeaderBase64() {
                return headerBase64;
            }

            @Override
            public String getPayloadBase64() {
                return payloadBase64;
            }

            @Override
            public String getSignatureBase64() {
                return signature;
            }
        };
    }
}
