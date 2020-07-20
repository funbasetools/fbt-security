package com.funbasetools.security.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public final class PemUtils {

    public static PemObject readPemObjectFrom(final InputStream inputStream) throws IOException {
        final PemReader pemReader = new PemReader(new InputStreamReader(inputStream));
        return pemReader.readPemObject();
    }

    private PemUtils() {
    }
}
