package com.funbasetools.security.jwt;

import static com.funbasetools.security.jwt.Jwt.JWT_CHARSET;
import static com.funbasetools.security.jwt.Jwt.SEPARATOR;

import com.funbasetools.Types;
import com.funbasetools.codecs.text.Base64Encoder;
import com.funbasetools.security.jwt.subtypes.Claim;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import org.apache.commons.lang3.tuple.Pair;

public final class JwtUtils {

    public static String getSectionBase64(final Function<Map<String, Object>, String> jsonEncoder,
                                          final Map<String, Object> sectionMap) {

        final String sectionJson = jsonEncoder.apply(sectionMap);
        final byte[] sectionBytes = sectionJson.getBytes(JWT_CHARSET);

        return Base64Encoder.URL_NO_PADDING.encode(sectionBytes);
    }

    public static byte[] getJwtContentBytes(final Function<Map<String, Object>, String> jsonEncoder,
                                            final Map<String, Object> headerMap,
                                            final Map<String, Object> payloadMap) {

        final String headerBase64 = getSectionBase64(jsonEncoder, headerMap);
        final String payloadBase64 = getSectionBase64(jsonEncoder, payloadMap);

        return String
            .format("%s%c%s", headerBase64, SEPARATOR, payloadBase64)
            .getBytes(JWT_CHARSET);
    }

    public static Map<String, Object> getMapFrom(final Map<String, Claim> claimMap) {
        return claimMap
            .entrySet()
            .stream()
            .map(entry ->
                Pair.of(
                    entry.getKey(),
                    entry.getValue().asObject()
                )
            )
            .collect(
                LinkedHashMap::new,
                (linkedHashMap, item) -> linkedHashMap.put(item.getKey(), item.getValue()),
                Map::putAll
            );
    }

    public static Map<String, Claim> getClaimsFrom(final Map<String, Object> map) {
        return getClaimsFrom(map, Function.identity());
    }

    public static Map<String, Claim> getClaimsFrom(final Map<String, Object> map,
                                                   final Function<Object, Object> mapper) {
        return map
            .entrySet()
            .stream()
            .map(entry ->
                Pair.of(
                    entry.getKey(),
                    getClaimOf(mapper.apply(entry.getValue()))
                )
            )
            .collect(
                LinkedHashMap::new,
                (linkedHashMap, item) -> linkedHashMap.put(item.getKey(), item.getValue()),
                Map::putAll
            );
    }

    private static Claim getClaimOf(final Object obj) {
        return new Claim() {
            @Override
            public boolean isNull() {
                return false;
            }

            @Override
            public <T> boolean isArrayOf(Class<T> type) {
                return Types.isArrayOf(type, obj);
            }

            @Override
            public Object asObject() {
                return obj;
            }

            @Override
            public boolean asBoolean() {
                return Optional
                    .ofNullable(Types.as(Boolean.class, obj))
                    .orElseGet(() -> Boolean.parseBoolean(asString()));
            }

            @Override
            public byte asByte() {
                return Optional
                    .ofNullable(Types.as(Byte.class, obj))
                    .orElseGet(() -> Byte.parseByte(asString()));
            }

            @Override
            public short asShort() {
                return Optional
                    .ofNullable(Types.as(Short.class, obj))
                    .orElseGet(() -> Short.parseShort(asString()));
            }

            @Override
            public int asInt() {
                return Optional
                    .ofNullable(Types.as(Integer.class, obj))
                    .orElseGet(() -> Integer.parseInt(asString()));
            }

            @Override
            public long asLong() {
                return Optional
                    .ofNullable(Types.as(Long.class, obj))
                    .orElseGet(() -> Long.parseLong(asString()));
            }

            @Override
            public double asDouble() {
                return Optional
                    .ofNullable(Types.as(Double.class, obj))
                    .orElseGet(() -> Double.parseDouble(asString()));
            }

            @Override
            public float asFloat() {
                return Optional
                    .ofNullable(Types.as(Float.class, obj))
                    .orElseGet(() -> Float.parseFloat(asString()));
            }

            @Override
            public BigInteger asBigInteger() {
                return Optional
                    .ofNullable(Types.as(BigInteger.class, obj))
                    .orElseGet(() -> new BigInteger(asString()));
            }

            @Override
            public BigDecimal asBigDecimal() {
                return Optional
                    .ofNullable(Types.as(BigDecimal.class, obj))
                    .orElseGet(() -> new BigDecimal(asString()));
            }

            @Override
            public String asString() {
                return Objects.toString(obj);
            }

            @Override
            public LocalDateTime asDateTime() {
                return Optional
                    .ofNullable(Types.as(LocalDateTime.class, obj))
                    .orElseGet(() -> LocalDateTime.parse(asString()));
            }

            @Override
            public <T> T[] asArrayOf(Class<T> type) {
                return Types.asArrayOf(type, true, obj);
            }

            @Override
            public <T> List<T> asListOf(Class<T> type) {
                return Optional
                    .ofNullable(asArrayOf(type))
                    .map(Arrays::asList)
                    .orElse(null);
            }

            @Override
            public Map<String, Object> asMap() {
                return Types.asMapOf(String.class, Object.class, true, obj);
            }

            @Override
            public <T> T as(Class<T> type) {
                return Types.as(type, obj);
            }
        };
    }

    private JwtUtils() {
    }
}
