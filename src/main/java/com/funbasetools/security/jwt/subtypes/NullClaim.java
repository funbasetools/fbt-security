package com.funbasetools.security.jwt.subtypes;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public final class NullClaim implements Claim {

    static final NullClaim INSTANCE = new NullClaim();

    private NullClaim() {
    }

    @Override
    public boolean isNull() {
        return true;
    }

    @Override
    public <T> boolean isArrayOf(Class<T> type) {
        return false;
    }

    @Override
    public Object asObject() {
        return null;
    }

    @Override
    public boolean asBoolean() {
        return false;
    }

    @Override
    public byte asByte() {
        return 0;
    }

    @Override
    public short asShort() {
        return 0;
    }

    @Override
    public int asInt() {
        return 0;
    }

    @Override
    public long asLong() {
        return 0;
    }

    @Override
    public double asDouble() {
        return 0;
    }

    @Override
    public float asFloat() {
        return 0;
    }

    @Override
    public BigInteger asBigInteger() {
        return null;
    }

    @Override
    public BigDecimal asBigDecimal() {
        return null;
    }

    @Override
    public String asString() {
        return null;
    }

    @Override
    public LocalDateTime asDateTime() {
        return null;
    }

    @Override
    public <T> T[] asArrayOf(Class<T> type) {
        return null;
    }

    @Override
    public <T> List<T> asListOf(Class<T> type) {
        return null;
    }

    @Override
    public Map<String, Object> asMap() {
        return null;
    }

    @Override
    public <T> T as(Class<T> type) {
        return null;
    }
}
