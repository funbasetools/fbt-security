package com.funbasetools.security.crypto;

import static com.funbasetools.security.TestHelper.EC224_PRIVATE_KEY;
import static com.funbasetools.security.TestHelper.EC224_PUBLIC_KEY;
import static com.funbasetools.security.TestHelper.EC256_PRIVATE_KEY;
import static com.funbasetools.security.TestHelper.EC256_PUBLIC_KEY;
import static com.funbasetools.security.TestHelper.EC384_PRIVATE_KEY;
import static com.funbasetools.security.TestHelper.EC384_PUBLIC_KEY;
import static com.funbasetools.security.TestHelper.EC512_PRIVATE_KEY;
import static com.funbasetools.security.TestHelper.EC512_PUBLIC_KEY;
import static com.funbasetools.security.TestHelper.RSA_PRIVATE_KEY;
import static com.funbasetools.security.TestHelper.RSA_PUBLIC_KEY;
import static com.funbasetools.security.TestHelper.getPrivateKeyFromResource;
import static com.funbasetools.security.TestHelper.getPublicKeyFromResources;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.funbasetools.codecs.text.HexText;
import com.funbasetools.security.crypto.providers.KeyProviders;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.Test;

public class SignatureAlgorithmTest {

    @Test
    public void testHmacSha1Signature() throws GeneralSecurityException {
        // given
        final Charset utf8 = StandardCharsets.UTF_8;
        final byte[] secret = "my-secret".getBytes(utf8);
        final byte[] data = "Hello World!!".getBytes(utf8);

        final SignatureAlgorithm algorithm = SignatureAlgorithms.getHmacSha1(secret);
        final String expectedSignature = "95eceae226deca5159fce83bc77aed7161464da4";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testHmacSha224Signature() throws GeneralSecurityException {
        // given
        final Charset utf8 = StandardCharsets.UTF_8;
        final byte[] secret = "my-secret".getBytes(utf8);
        final byte[] data = "Hello World!!".getBytes(utf8);

        final SignatureAlgorithm algorithm = SignatureAlgorithms.getHmacSha224(secret);
        final String expectedSignature = "ed32d90a673ca870f1d6cbcaa919498ddf780f85c505c21f0455067e";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testHmacSha256Signature() throws GeneralSecurityException {
        // given
        final Charset utf8 = StandardCharsets.UTF_8;
        final byte[] secret = "my-secret".getBytes(utf8);
        final byte[] data = "Hello World!!".getBytes(utf8);

        final SignatureAlgorithm algorithm = SignatureAlgorithms.getHmacSha256(secret);
        final String expectedSignature = "d8a8a3f2e44b973c22ce8bac348cf2359d59755e50fa931c872396c976567b6a";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testHmacSha384Signature() throws GeneralSecurityException {
        // given
        final Charset utf8 = StandardCharsets.UTF_8;
        final byte[] secret = "my-secret".getBytes(utf8);
        final byte[] data = "Hello World!!".getBytes(utf8);

        final SignatureAlgorithm algorithm = SignatureAlgorithms.getHmacSha384(secret);
        final String expectedSignature = "350b53626a5795809e8f67fbd72af21cf334f6a3f5492671828cf9d1972e0b9e75f160cc32202cbed74c1ea5b8cf42e8";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testHmacSha512Signature() throws GeneralSecurityException {
        // given
        final Charset utf8 = StandardCharsets.UTF_8;
        final byte[] secret = "my-secret".getBytes(utf8);
        final byte[] data = "Hello World!!".getBytes(utf8);

        final SignatureAlgorithm algorithm = SignatureAlgorithms.getHmacSha512(secret);
        final String expectedSignature = "e1d8ae2d47b5df809cf342d42e0ac78b59aaf6c4bf095e85c27f6f7674f85e2dc0ea1c44f652f71a6530c8792b50f98330aa4d2388ec5bc9e942fbc69e834f61";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha1WithRsaSignature() throws Exception {
        // given
        final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromResources(PemKeyType.RSA, RSA_PUBLIC_KEY);
        final RSAPrivateKey prvKey = (RSAPrivateKey) getPrivateKeyFromResource(PemKeyType.RSA, RSA_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getRSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha1WithRsa(keyProvider);
        final String expectedSignature = "6facd7f2118ddcb6c13429887e4932b0202a0741dcdc786d85429c94c10fa64278b16bca3a50394860aac9ca13e7c08d20de92e45d28c67a45e2fda8ee868e7b43c6c9f53d7f2ed0b6954abeee348ae9c134873d86d1187caa0b22b08930bdacc4ab75027ccaf5704f3818caa7b1a1b0c893334d7167eeb7669e188c3af15c6247f65a4a54ddae756a6a176326b64090762063398425265d9f8b514b311ea71efd3ec911119fd4b4d60e575bb5acfafb22cd67301b572ca6b2fe8eb32bdaf2bb75c3afdf43dcebdf0012836fb10432072e5d158ca3f4d71b15f15015655394b39e889dc628f964bddd773d21cfd3fb702f4c958b9c5af7eaa10f34b613d59f62";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha224WithRsaSignature() throws Exception {
        // given
        final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromResources(PemKeyType.RSA, RSA_PUBLIC_KEY);
        final RSAPrivateKey prvKey = (RSAPrivateKey) getPrivateKeyFromResource(PemKeyType.RSA, RSA_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getRSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha224WithRsa(keyProvider);
        final String expectedSignature = "8f1f21bf33d0d765e402891745bf79abfc1e0c6f5b8dbfccd5734c8bda7cb09669b940707018d46b7f960b88763692c7def7c202b17ada1d267fb1990cfd2ecf4756161cd1cc716036032cd89fc2b7e82d44c34c70972274da715f6b399c765f9f5ed0fc4bf1f50a33d16b18a9f032bc2cae9fb55ebf1cd6eb355361df8308a89c02c9a363304e2ec88027627de182471f845816946e1210ddf8f5e28a19b7c75132558bed5236e1c82da5fd513aff1ab761317ff0431c4babd0df54c098dd2155a493301e8660978aa789e837b081c48ada864afc8602a46d23a735a55545b24043e912ce9dda8050ada258c19065cf8bbd3efebc4abb7acb0d6860adda4b67";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha256WithRsaSignature() throws Exception {
        // given
        final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromResources(PemKeyType.RSA, RSA_PUBLIC_KEY);
        final RSAPrivateKey prvKey = (RSAPrivateKey) getPrivateKeyFromResource(PemKeyType.RSA, RSA_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getRSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha256WithRsa(keyProvider);
        final String expectedSignature = "8175690cb0098ba8e3e9f10f10ac86a7b7b9f16312a5ea22c71235bff772e3bd2ce58ba2661208c19e36a0004f23c902272d929eeb79c556bc0323ebf20953d6cb80c6fa9ad16136842bb876e276861020f0e404c4c309a14ea54e914aedb1e9e827427dd1029da0925770ff7ec0a1c62d3564d7ecfb5523936a231d5c6bf18be2e11f7a9b60296f1d02ec600b5e31fc3525bbc652620e5b775c6ab68b335b653cba6d662133c072bd28a0c366347507429d3deac0ba0c2a9f89a4993810ef100ddc75ef8eff2e02696259eecf9fca376308b11eb5983bb432fb4c552fd98672ce901a9e34c2673b3a3af70b6ba8dbdcb787a045ff1db8199febae0e3cbb1213";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha384WithRsaSignature() throws Exception {
        // given
        final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromResources(PemKeyType.RSA, RSA_PUBLIC_KEY);
        final RSAPrivateKey prvKey = (RSAPrivateKey) getPrivateKeyFromResource(PemKeyType.RSA, RSA_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getRSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha384WithRsa(keyProvider);
        final String expectedSignature = "07add689e124d8ff0ac95d37a21f5a847f501e63fb861bcb3918f8e88f5141f737d03be2fc72be0523d1ca9760edff045f8d243243463a5bcdd10623ca577ccb09ffa53917f6eaa4858e29951e339a2e3ed65bf4d00d97974bad9b175e7290b1319d2b031760f65087951fdba99c2a35f436610cb0cce8768994ecc255cab4a841c71dd4d3b80536ddfa14108ea9c94036dc797d72c558d78d6e86ecc200c49184efe7e3b8fed3160d6c76c17de3f5c44de720121f163ebcd4bb0035ac7206ff53879d7747aae4c63b22b7427a9419d5b6e7a22704061863cf2d03fd328b870ff20d8583aa1b739e975a8943cca3caf7b1feb96d1ebd861ae9071977cf682d3e";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha512WithRsaSignature() throws Exception {
        // given
        final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromResources(PemKeyType.RSA, RSA_PUBLIC_KEY);
        final RSAPrivateKey prvKey = (RSAPrivateKey) getPrivateKeyFromResource(PemKeyType.RSA, RSA_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getRSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha512WithRsa(keyProvider);
        final String expectedSignature = "544b713bad80598c00d2985c8a9c598ad6ba6cea76fc4570272775a56b69e278cbae414f4f2e31ad999726bc68986db0c2e2a9adc417b9b8a5130791bd6a97087ed320d51cc87b987da102dc9a745bb30cd8bb583cc8988e2b781f17322a1399964ff05f4fcfe9aee7bdc785de976f8e1bbc01e55356f2c5fd20e73de8e16a89fed332504d4290ddbf19277bf59eb7912e06ad22eea9ac5f902d9060d7ba61c2839120bf5409daa061324461c66922e58bb92ae455a6ab67c59750ad1c136557e739e37d398a030531e95f9bab6e2ac207037bc7e293093abb6b6a3623f6b1e45b9e7ab6dacf2d40bab1fd862f94c542157da19e684e0fc933da3d460b5d02cf";

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertEquals(
            String.format("Hash should be equal to %s", expectedSignature),
            expectedSignature,
            HexText.getEncoder().encode(signature)
        );
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha224WithEcdsaSignature() throws Exception {
        // given
        final ECPublicKey pubKey = (ECPublicKey) getPublicKeyFromResources(PemKeyType.EC, EC224_PUBLIC_KEY);
        final ECPrivateKey prvKey = (ECPrivateKey) getPrivateKeyFromResource(PemKeyType.EC, EC224_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getECDSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha224WithEcdsa(keyProvider);

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha256WithEcdsaSignature() throws Exception {
        // given
        final ECPublicKey pubKey = (ECPublicKey) getPublicKeyFromResources(PemKeyType.EC, EC256_PUBLIC_KEY);
        final ECPrivateKey prvKey = (ECPrivateKey) getPrivateKeyFromResource(PemKeyType.EC, EC256_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getECDSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha256WithEcdsa(keyProvider);

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha384WithEcdsaSignature() throws Exception {
        // given
        final ECPublicKey pubKey = (ECPublicKey) getPublicKeyFromResources(PemKeyType.EC, EC384_PUBLIC_KEY);
        final ECPrivateKey prvKey = (ECPrivateKey) getPrivateKeyFromResource(PemKeyType.EC, EC384_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getECDSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha384WithEcdsa(keyProvider);

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertTrue(algorithm.verify(data, signature));
    }

    @Test
    public void testSha512WithEcdsaSignature() throws Exception {
        // given
        final ECPublicKey pubKey = (ECPublicKey) getPublicKeyFromResources(PemKeyType.EC, EC512_PUBLIC_KEY);
        final ECPrivateKey prvKey = (ECPrivateKey) getPrivateKeyFromResource(PemKeyType.EC, EC512_PRIVATE_KEY);

        final byte[] data = "Hello World!!".getBytes(StandardCharsets.UTF_8);

        final var keyProvider = KeyProviders.getECDSAKeyProvider(prvKey, pubKey);
        final SignatureAlgorithm algorithm = SignatureAlgorithms.getSha512WithEcdsa(keyProvider);

        // when
        final byte[] signature = algorithm.sign(data);

        // then
        assertTrue(algorithm.verify(data, signature));
    }
}
