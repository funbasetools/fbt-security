package com.funbasetools.security.jwt;

import static com.funbasetools.security.TestHelper.RSA_PRIVATE_KEY;
import static com.funbasetools.security.TestHelper.RSA_PUBLIC_KEY;
import static com.funbasetools.security.TestHelper.getPrivateKeyFromResource;
import static com.funbasetools.security.TestHelper.getPublicKeyFromResources;
import static com.funbasetools.security.TestHelper.jsonEncoder;
import static com.funbasetools.security.jwt.subtypes.Claim.ISSUED_AT_CLAIM;
import static com.funbasetools.security.jwt.subtypes.Claim.NAME_CLAIM;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.funbasetools.security.crypto.PemKeyType;
import com.funbasetools.security.crypto.SignatureAlgorithm;
import com.funbasetools.security.crypto.SignatureAlgorithms;
import com.funbasetools.security.crypto.providers.KeyProviders;
import com.funbasetools.security.crypto.providers.RSAKeyProvider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.Test;

public class JwtBuilderAndVerifierTest {

    @Test
    public void testBuildAndSignWithHS256() {
        // given
        final String secret = "12345";
        final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithms
            .getHmacSha256(secret.getBytes(Jwt.JWT_CHARSET));

        // when
        final DecodedJwt decodedJwt = new JwtBuilder()
            .withSubject("1234567890")
            .addClaim(NAME_CLAIM, "John Doe")
            .addClaim(ISSUED_AT_CLAIM, 1516239022)
            .buildAndSign(signatureAlgorithm, jsonEncoder());

        // then
        assertEquals("bgGd720CeHP4kY9mGuMEoteBq4TP4d0W2XkpiI4bVgg", decodedJwt.getSignature());

        // and given
        final JwtVerifier verifier = new JwtVerifier(jsonEncoder());

        // when
        final boolean verified = verifier.verify(decodedJwt, signatureAlgorithm);

        // then
        assertTrue(verified);
    }

    @Test
    public void testBuildAndSignWithRS256() throws Exception {
        // given
        final RSAKeyProvider keyProvider = KeyProviders.getRSAKeyProvider(
            (RSAPrivateKey) getPrivateKeyFromResource(PemKeyType.RSA, RSA_PRIVATE_KEY),
            (RSAPublicKey) getPublicKeyFromResources(PemKeyType.RSA, RSA_PUBLIC_KEY)
        );
        final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithms.getSha256WithRsa(keyProvider);

        // when
        final DecodedJwt decodedJwt = new JwtBuilder()
            .withSubject("1234567890")
            .addClaim(NAME_CLAIM, "John Doe")
            .addClaim(ISSUED_AT_CLAIM, 1516239022)
            .buildAndSign(signatureAlgorithm, jsonEncoder());

        // then
        assertEquals(
            "FyzcED6749ZNgvl9cqteBn3313tIT_tip7WQCF6LyUDWG5HBRQOHhOeFOpqgfyCxiSUDw8wu5PY9re3F3a9jyKUNuOYyfLqVuPkoNP3uZM6jtWjywHnhs5AtJKItPtvFulInOPCiTsaU9QEOUqLfbYF13SPX8D2V1wUHytz-7KzM825ctDn_H71kV8fZfSdM7b4R_9gfeW92h1kKtOumtvesHIR8b4cA6Vpkgj-MqJKYX_BdWrIkEmHNuv0MhArNcfAJC2oTRhp8a2H6v_z662TrCHVZaiMWghgHeOL60g5x--fWBvZdZiAjGVheQ5SPHB2mjTc0A9TysVhcPELNww",
            decodedJwt.getSignature()
        );

        // and given
        final JwtVerifier verifier = new JwtVerifier(jsonEncoder());

        // when
        final boolean verified = verifier.verify(decodedJwt, signatureAlgorithm);

        // then
        assertTrue(verified);
    }
}
