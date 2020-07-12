package com.funbasetools.security.crypto.providers;

import com.funbasetools.Try;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyProvider<PVK extends PrivateKey, PUK extends PublicKey> {

    Try<PVK> getPrivateKey();

    Try<PUK> getPublicKey();
}
