package com.funbasetools.security.jwt.subtypes;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public interface Claim {

    // header claims

    String ALGORITHM_CLAIM = "alg";
    String CONTENT_TYPE_CLAIM = "cty";
    String TYPE_CLAIM = "typ";
    String KEY_ID_CLAIM = "kid";

    // Payload claims

    String ADDRESS_CLAIM = "address";
    String AUDIENCE_CLAIM = "aud";
    String AUTHENTICATION_CONTEXT_CLASS_REFERENCE_CLAIM = "acr";
    String AUTHENTICATION_METHODS_REFERENCES_CLAIM = "amr";
    String AUTHENTICATION_TIME_CLAIM = "auth_time";
    String AUTHORIZED_PARTY_CLAIM = "azp";
    String AT_HASH_CLAIM = "at_hash";
    String BIRTH_DATE_CLAIM = "birthdate";
    String CODE_HASH_CLAIM = "c_hash";
    String EMAIL_CLAIM = "email";
    String EMAIL_VERIFIED_CLAIM = "email_verified";
    String EXPIRATION_TIME_CLAIM = "exp";
    String FAMILY_NAME_CLAIM = "family_name";
    String ISSUED_AT_CLAIM = "iat";
    String GENDER_CLAIM = "gender";
    String GIVEN_NAME_CLAIM = "given_name";
    String ID_TOKEN_PUBLIC_KEY_CLAIM = "sub_jwk";
    String ISSUER_CLAIM = "iss";
    String JWT_ID_CLAIM = "jti";
    String LOCALE_CLAIM = "locale";
    String MIDDLE_NAME_CLAIM = "middle_name";
    String NAME_CLAIM = "name";
    String NICKNAME_CLAIM = "nickname";
    String NONCE_CLAIM = "nonce";
    String NOT_BEFORE_CLAIM = "nbf";
    String PHONE_NUMBER_CLAIM = "phone_number";
    String PHONE_NUMBER_VERIFIED_CLAIM = "phone_number_verified";
    String PICTURE_CLAIM = "picture";
    String PREFERRED_USERNAME_CLAIM = "preferred_username";
    String PROFILE_CLAIM = "profile";
    String SUBJECT_CLAIM = "sub";
    String UPDATED_AT_CLAIM = "updated_at";
    String WEBSITE_CLAIM = "website";
    String ZONE_INFO_CLAIM = "zoneinfo";

    boolean isNull();
    <T> boolean isArrayOf(final Class<T> type);

    Object asObject();
    boolean asBoolean();
    byte asByte();
    short asShort();
    int asInt();
    long asLong();
    double asDouble();
    float asFloat();
    BigInteger asBigInteger();
    BigDecimal asBigDecimal();
    String asString();
    LocalDateTime asDateTime();

    <T> T[] asArrayOf(final Class<T> type);
    <T> List<T> asListOf(final Class<T> type);
    Map<String, Object> asMap();
    <T> T as(final Class<T> type);

    static Claim nullClaim() {
        return NullClaim.INSTANCE;
    }
}
