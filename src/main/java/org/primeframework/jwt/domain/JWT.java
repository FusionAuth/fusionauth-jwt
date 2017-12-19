/*
 * Copyright (c) 2016-2017, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.primeframework.jwt.JWTDecoder;
import org.primeframework.jwt.JWTEncoder;

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

  @JsonIgnore
  public Map<String, Object> claims = new LinkedHashMap<>();

  /**
   * Registered Claim <code>exp</code> as defined by RFC 7519 Section 4.1.4. Use of this claim is OPTIONAL.
   * <p>
   * The expiration time claim identifies the expiration time on or after which the JWT MUST NOT be accepted for
   * processing. The expiration time is expected to provided in UNIX time, or the number of seconds since Epoch.
   */
  @JsonProperty("exp")
  public ZonedDateTime expiration;

  /**
   * Registered Claim <code>iat</code> as defined by RFC 7519 Section 4.1.6. Use of this claim is OPTIONAL.
   * <p>
   * The issued at claim identifies the time at which the JWT was issued. The issued at time is expected to provided in
   * UNIX time, or the number of seconds since Epoch.
   */
  @JsonProperty("iat")
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
  public ZonedDateTime notBefore;

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
   * Return a singleton instance of the JWT Decoder.
   *
   * @return a JWT decoder.
   */
  public static JWTDecoder getDecoder() {
    return JWTDecoder.getInstance();
  }

  /**
   * Return a singleton instance of the JWT encoder.
   *
   * @return a JWT encoder.
   */
  public static JWTEncoder getEncoder() {
    return JWTEncoder.getInstance();
  }

  /**
   * Add a claim to this JWT. This claim can be public or private, it is up to the caller to properly name the claim as
   * to avoid collision.
   *
   * @param name  The name of the JWT claim.
   * @param value The value of the JWT claim. This value is an object and is expected to properly serialize.
   * @return this.
   */
  @JsonAnySetter
  public JWT addClaim(String name, Object value) {
    if (value != null) {
      claims.put(name, value);
    }
    return this;
  }

  /**
   * Special getter used to flatten the claims into top level properties. Necessary to correctly serialize this object.
   */
  @JsonAnyGetter
  public Map<String, Object> anyGetter() {
    return claims;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    JWT jwt = (JWT) o;
    return Objects.equals(audience, jwt.audience) &&
        Objects.equals(claims, jwt.claims) &&
        Objects.equals(expiration, jwt.expiration) &&
        Objects.equals(issuedAt, jwt.issuedAt) &&
        Objects.equals(issuer, jwt.issuer) &&
        Objects.equals(notBefore, jwt.notBefore) &&
        Objects.equals(subject, jwt.subject) &&
        Objects.equals(uniqueId, jwt.uniqueId);
  }

  public Boolean getBoolean(String key) {
    Object object = claims.get(key);
    if (object == null) {
      return null;
    }

    if (object instanceof String) {
      return Boolean.valueOf((String) object);
    }

    return (Boolean) object;
  }

  public Integer getInteger(String key) {
    Object object = claims.get(key);
    if (object == null) {
      return null;
    }

    if (object instanceof String) {
      return Integer.parseInt((String) object);
    }

    return (Integer) object;
  }

  public List<String> getList(String key) {
    Object object = claims.get(key);
    if (object == null) {
      return null;
    }

    return (List<String>) object;
  }

  public Long getLong(String key) {
    Object object = claims.get(key);
    if (object == null) {
      return null;
    }

    if (object instanceof String) {
      return Long.parseLong((String) object);
    } else if (object instanceof Integer) {
      return ((Integer) object).longValue();
    }

    return (Long) object;
  }

  public Object getObject(String key) {
    if (key == null) {
      return null;
    }

    if (key.equals("aud")) {
      return audience;
    }
    return claims.get(key);
  }

  @JsonIgnore
  public Map<String, Object> getRawClaims() {
    Map<String, Object> rawClaims = new HashMap<>(claims);

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
    if (key == null) {
      return null;
    }

    if (key.equals("sub")) {
      return subject;
    } else if (key.equals("jti")) {
      return uniqueId;
    } else if (key.equals("iss")) {
      return issuer;
    }
    return (String) claims.get(key);
  }

  @Override
  public int hashCode() {
    return Objects.hash(audience, claims, expiration, issuedAt, issuer, notBefore, subject, uniqueId);
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
}
