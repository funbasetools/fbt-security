package com.funbasetools.security.crypto;

import com.funbasetools.Algorithm;
import com.funbasetools.ShouldNotReachThisPointException;
import com.funbasetools.Try;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Optional;

public interface SignatureAlgorithm extends Algorithm {

    byte[] sign(final InputStream content) throws IOException, GeneralSecurityException;

    default boolean verify(final InputStream content, byte[] signature) {
        final byte[] safeSignature = Optional
            .ofNullable(signature)
            .orElseGet(() -> new byte[0]);

        return Try
            .of(() -> MessageDigest.isEqual(sign(content), safeSignature))
            .toOptional()
            .orElse(false);
    }

    default byte[] sign(final byte[] content) throws GeneralSecurityException {
        final byte[] safeContent = Optional
            .ofNullable(content)
            .orElseGet(() -> new byte[0]);

        return Try
            .of(() -> sign(new ByteArrayInputStream(safeContent)))
            .throwIfFailureWith(GeneralSecurityException.class)
            .toOptional()
            .orElseThrow(ShouldNotReachThisPointException::new);
    }

    default boolean verify(final byte[] content, byte[] signature) {
        final byte[] safeContent = Optional
            .ofNullable(content)
            .orElseGet(() -> new byte[0]);

        final byte[] safeSignature = Optional
            .ofNullable(signature)
            .orElseGet(() -> new byte[0]);

        return verify(new ByteArrayInputStream(safeContent), safeSignature);
    }
}
