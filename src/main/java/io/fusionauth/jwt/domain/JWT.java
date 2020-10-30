/*
 * Copyright (c) 2016-2019, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package io.fusionauth.jwt.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.fusionauth.jwt.JWTDecoder;
import io.fusionauth.jwt.JWTEncoder;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.jwt.json.ZonedDateTimeSerializer;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * JSON Web Token (JWT) as defined by RFC 7519.
 * <pre>
 * From RFC 7519 Section 1. Introduction:
 *    The suggested pronunciation of JWT is the same as the English word "jot".
 * </pre>
 * The JWT is not Thread-Safe and should not be re-used.
 *
 * @author Daniel DeGroff
 */
public class JWT {

  /**
   * Registered Claim <code>aud</code> as defined by RFC 7519 Section 4.1.3. Use of this claim is OPTIONAL.
   * <p>
   * The audience claim identifies the recipients that the JWT is intended for. This may be an array of strings or a
   * single string, in either case if the string value contains a <code>:</code> it must be a URI.
   */
  @JsonProperty("aud")
  public Object audience;

  /**
   * Registered Claim <code>exp</code> as defined by RFC 7519 Section 4.1.4. Use of this claim is OPTIONAL.
   * <p>
   * The expiration time claim identifies the expiration time on or after which the JWT MUST NOT be accepted for
   * processing. The expiration time is expected to provided in UNIX time, or the number of seconds since Epoch.
   */
  @JsonProperty("exp")
  @JsonSerialize(using = ZonedDateTimeSerializer.class)
  public ZonedDateTime expiration;

  /**
   * Registered Claim <code>iat</code> as defined by RFC 7519 Section 4.1.6. Use of this claim is OPTIONAL.
   * <p>
   * The issued at claim identifies the time at which the JWT was issued. The issued at time is expected to provided in
   * UNIX time, or the number of seconds since Epoch.
   */
  @JsonProperty("iat")
  @JsonSerialize(using = ZonedDateTimeSerializer.class)
  public ZonedDateTime issuedAt;

  /**
   * Registered Claim <code>iss</code> as defined by RFC 7519 Section 4.1.1. Use of this claim is OPTIONAL.
   * <p>
   * The issuer claim identifies the principal that issued the JWT. If the value contains a <code>:</code> it must be a
   * URI.
   */
  @JsonProperty("iss")
  public String issuer;

  /**
   * Registered Claim <code>nbf</code> as defined by RFC 7519 Section 4.1.5. Use of this claim is OPTIONAL.
   * <p>
   * This claim identifies the time before which the JWT MUST NOT be accepted for processing. The not before value is
   * expected to provided in UNIX time, or the number of seconds since Epoch.
   */
  @JsonProperty("nbf")
  @JsonSerialize(using = ZonedDateTimeSerializer.class)
  public ZonedDateTime notBefore;

  /**
   * This Map will contain all the claims that aren't specifically defined in the specification. These still might be
   * IANA registered claims, but are not known JWT specification claims.
   */
  @JsonAnySetter
  public Map<String, Object> otherClaims = new LinkedHashMap<>();

  /**
   * Registered Claim <code>sub</code> as defined by RFC 7519 Section 4.1.2. Use of this claim is OPTIONAL.
   * <p>
   * The subject claim identifies the principal that is the subject of the JWT. If the value contains a <code>:</code>
   * it must be a URI.
   */
  @JsonProperty("sub")
  public String subject;

  /**
   * Registered Claim <code>jti</code> as defined by RFC 7519 Section 4.1.7. Use of this claim is OPTIONAL.
   * <p>
   * The JWT unique ID claim provides a unique identifier for the JWT.
   */
  @JsonProperty("jti")
  public String uniqueId;

  /**
   * Return an instance of the JWT Decoder.
   *
   * @return a JWT decoder.
   */
  public static JWTDecoder getDecoder() {
    return new JWTDecoder();
  }

  /**
   * Return an instance of the JWT encoder.
   *
   * @return a JWT encoder.
   */
  public static JWTEncoder getEncoder() {
    return new JWTEncoder();
  }

  /**
   * Add a claim to this JWT. This claim can be public or private, it is up to the caller to properly name the claim as
   * to avoid collision.
   *
   * @param name  The name of the JWT claim.
   * @param value The value of the JWT claim. This value is an object and is expected to properly serialize.
   * @return this.
   */
  public JWT addClaim(String name, Object value) {
    if (value == null) {
      return this;
    }

    switch (name) {
      case "aud":
        this.audience = value;
        break;
      case "exp":
        this.expiration = toZonedDateTime("exp", value);
        break;
      case "iat":
        this.issuedAt = toZonedDateTime("iat", value);
        break;
      case "iss":
        this.issuer = (String) value;
        break;
      case "jti":
        this.uniqueId = (String) value;
        break;
      case "nbf":
        this.notBefore = toZonedDateTime("nbf", value);
        break;
      case "sub":
        this.subject = (String) value;
        break;
      default:
        if (value instanceof Double || value instanceof Float) {
          value = BigDecimal.valueOf(((Number) value).doubleValue());
        } else if (value instanceof Integer || value instanceof Long) {
          value = BigInteger.valueOf(((Number) value).longValue());
        }
        otherClaims.put(name, value);
        break;
    }
    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    JWT jwt = (JWT) o;
    return Objects.equals(audience, jwt.audience) &&
        Objects.equals(otherClaims, jwt.otherClaims) &&
        Objects.equals(expiration, jwt.expiration) &&
        Objects.equals(issuedAt, jwt.issuedAt) &&
        Objects.equals(issuer, jwt.issuer) &&
        Objects.equals(notBefore, jwt.notBefore) &&
        Objects.equals(subject, jwt.subject) &&
        Objects.equals(uniqueId, jwt.uniqueId);
  }

  /**
   * @return Returns all the claims as cool Java types like ZonedDateTime (where appropriate of course). This will
   * contain the otherClaims and the known JWT claims.
   */
  @JsonIgnore
  public Map<String, Object> getAllClaims() {
    Map<String, Object> rawClaims = new HashMap<>(otherClaims);

    if (audience != null) {
      rawClaims.put("aud", audience);
    }

    if (expiration != null) {
      rawClaims.put("exp", expiration);
    }

    if (issuedAt != null) {
      rawClaims.put("iat", issuedAt);
    }

    if (issuer != null) {
      rawClaims.put("iss", issuer);
    }

    if (notBefore != null) {
      rawClaims.put("nbf", notBefore);
    }

    if (subject != null) {
      rawClaims.put("sub", subject);
    }

    if (uniqueId != null) {
      rawClaims.put("jti", uniqueId);
    }

    return rawClaims;
  }

  public BigDecimal getBigDecimal(String key) {
    return (BigDecimal) lookupClaim(key);
  }

  public BigInteger getBigInteger(String key) {
    return (BigInteger) lookupClaim(key);
  }

  public Boolean getBoolean(String key) {
    return (Boolean) lookupClaim(key);
  }

  public Double getDouble(String key) {
    BigDecimal value = (BigDecimal) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.doubleValue();
  }

  public Float getFloat(String key) {
    BigDecimal value = (BigDecimal) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.floatValue();
  }

  public Integer getInteger(String key) {
    BigInteger value = (BigInteger) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.intValue();
  }

  public List<Object> getList(String key) {
    return (List<Object>) otherClaims.get(key);
  }

  public Long getLong(String key) {
    BigInteger value = (BigInteger) lookupClaim(key);
    if (value == null) {
      return null;
    }

    return value.longValue();
  }

  public Map<String, Object> getMap(String key) {
    return (Map<String, Object>) lookupClaim(key);
  }

  public Number getNumber(String key) {
    return (Number) lookupClaim(key);
  }

  public Object getObject(String key) {
    return lookupClaim(key);
  }

  @JsonAnyGetter
  public Map<String, Object> getOtherClaims() {
    return otherClaims;
  }

  /**
   * @return Returns the original claims from the JWT without any Java data types like ZonedDateTime. This will contain
   * the otherClaims and the known JWT claims.
   */
  @JsonIgnore
  public Map<String, Object> getRawClaims() {
    Map<String, Object> rawClaims = new HashMap<>(otherClaims);

    if (audience != null) {
      rawClaims.put("aud", audience);
    }

    if (expiration != null) {
      rawClaims.put("exp", expiration.toEpochSecond());
    }

    if (issuedAt != null) {
      rawClaims.put("iat", issuedAt.toEpochSecond());
    }

    if (issuer != null) {
      rawClaims.put("iss", issuer);
    }

    if (notBefore != null) {
      rawClaims.put("nbf", notBefore.toEpochSecond());
    }

    if (subject != null) {
      rawClaims.put("sub", subject);
    }

    if (uniqueId != null) {
      rawClaims.put("jti", uniqueId);
    }

    return rawClaims;
  }

  public String getString(String key) {
    return (String) lookupClaim(key);
  }

  @Override
  public int hashCode() {
    return Objects.hash(audience, otherClaims, expiration, issuedAt, issuer, notBefore, subject, uniqueId);
  }

  /**
   * Return true if this JWT is expired.
   *
   * @return true if expired, false if not.
   */
  @JsonIgnore
  public boolean isExpired() {
    return expiration != null && expiration.isBefore(ZonedDateTime.now(ZoneOffset.UTC));
  }

  /**
   * Return true if this JWT is expired.
   *
   * @param clockSkew the number of seconds of clock skew allowed when calculating the expiration.
   * @return true if expired, false if not.
   */
  @JsonIgnore
  public boolean isExpired(int clockSkew) {
    return expiration != null && expiration.isBefore(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(clockSkew));
  }

  /**
   * Return true if this JWT is un-available for processing.
   *
   * @param clockSkew the number of seconds of clock skew allowed when calculating the notBefore instant.
   * @return true if un-available, false if not.
   */
  @JsonIgnore
  public boolean isUnavailableForProcessing(int clockSkew) {
    return notBefore != null && notBefore.isAfter(ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(clockSkew));
  }

  /**
   * Return true if this JWT is un-available for processing.
   *
   * @return true if un-available, false if not.
   */
  @JsonIgnore
  public boolean isUnavailableForProcessing() {
    return notBefore != null && notBefore.isAfter(ZonedDateTime.now(ZoneOffset.UTC));
  }

  public JWT setAudience(Object audience) {
    this.audience = audience;
    return this;
  }

  public JWT setExpiration(ZonedDateTime expiration) {
    this.expiration = expiration;
    return this;
  }

  public JWT setIssuedAt(ZonedDateTime issuedAt) {
    this.issuedAt = issuedAt;
    return this;
  }

  public JWT setIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public JWT setNotBefore(ZonedDateTime notBefore) {
    this.notBefore = notBefore;
    return this;
  }

  public JWT setSubject(String subject) {
    this.subject = subject;
    return this;
  }

  public JWT setUniqueId(String uniqueId) {
    this.uniqueId = uniqueId;
    return this;
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }

  private Object lookupClaim(String key) {
    switch (key) {
      case "aud":
        return audience;
      case "exp":
        return expiration;
      case "iat":
        return issuedAt;
      case "iss":
        return issuer;
      case "jti":
        return uniqueId;
      case "nbf":
        return notBefore;
      case "sub":
        return subject;
      default:
        return otherClaims.get(key);
    }
  }

  private ZonedDateTime toZonedDateTime(String claim, Object value) {
    if (value instanceof ZonedDateTime) {
      return (ZonedDateTime) value;
    } else if (value instanceof Number) {
      return Instant.ofEpochSecond(((Number) value).longValue()).atZone(ZoneOffset.UTC);
    } else {
      throw new IllegalArgumentException("Invalid numeric value for [" + claim + "] claim");
    }
  }
}
