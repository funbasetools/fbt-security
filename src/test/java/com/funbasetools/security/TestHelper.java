package com.funbasetools.security;

import com.funbasetools.Types;
import com.funbasetools.security.crypto.PemKeyType;
import com.funbasetools.security.crypto.providers.KeyProviders;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.Pair;

public final class TestHelper {

    public static final String EC224_PRIVATE_KEY = "ec224-private.pem";
    public static final String EC224_PUBLIC_KEY = "ec224-public.pem";
    public static final String EC256_PRIVATE_KEY = "ec256-private.pem";
    public static final String EC256_PUBLIC_KEY = "ec256-public.pem";
    public static final String EC384_PRIVATE_KEY = "ec384-private.pem";
    public static final String EC384_PUBLIC_KEY = "ec384-public.pem";
    public static final String EC512_PRIVATE_KEY = "ec512-private.pem";
    public static final String EC512_PUBLIC_KEY = "ec512-public.pem";
    public static final String RSA_PRIVATE_KEY = "rsa-private.pem";
    public static final String RSA_PUBLIC_KEY = "rsa-public.pem";

    public static PrivateKey getPrivateKeyFromResource(final PemKeyType keyType, final String fileName) throws Exception {
        final String path = String.format("src/test/resources/%s", fileName);
        try (final FileInputStream fileInputStream = new FileInputStream(path)) {
            return KeyProviders.getPrivateKey(keyType, fileInputStream);
        }
    }

    public static PublicKey getPublicKeyFromResources(final PemKeyType keyType, final String fileName) throws Exception {
        final String path = String.format("src/test/resources/%s", fileName);
        try (final FileInputStream fileInputStream = new FileInputStream(path)) {
            return KeyProviders.getPublicKey(keyType, fileInputStream);
        }
    }

    public static Function<Map<String, Object>, String> jsonEncoder() {
        return map -> new Gson().toJson(map);
    }

    public static Function<String, Map<String, Object>> jsonParser() {
        return json -> {
            final JsonObject jsonObj = JsonParser.parseString(json).getAsJsonObject();
            return jsonObj
                .keySet()
                .stream()
                .map(k -> {
                    final JsonElement jsonElement = jsonObj.get(k);

                    return Pair.of(k, jsonElement);
                })
                .collect(Collectors.toMap(Pair::getKey, Pair::getValue));
        };
    }

    public static Function<Object, Object> jsonObjectMapper() {
        return obj -> Optional
            .ofNullable(Types.as(JsonPrimitive.class, obj))
            .map(primitive -> {
                if (primitive.isBoolean()) {
                    return primitive.getAsBoolean();
                }

                return primitive.getAsString();
            })
            .orElse(null);
    }

    private TestHelper() {
    }
}
