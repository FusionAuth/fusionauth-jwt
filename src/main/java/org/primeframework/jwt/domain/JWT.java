/*
 * Copyright (c) 2016, Inversoft Inc., All Rights Reserved
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

import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON Web Token (JWT) as defined by RFC 7519.
 * <pre>
 * From RFC 7519 Section 1. Introduction:
 *    The suggested pronunciation of JWT is the same as the English word "jot".
 * </pre>
 *
 * @author Daniel DeGroff
 */
public class JWT {

  /**
   * Registered Claim <code>aud</code> as defined by RFC 7519 Section 4.1.3. Use of this claim is OPTIONAL.
   * <p>
   * The subject claim identifies the principal that is the subject of the JWT. This may be an array of
   * strings or a single string, in either case if the string value contains a <code>:</code> it must be
   * a URI.
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

  private JWT() {

  }

  public static Builder Builder() {
    return new Builder();
  }

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
   * Special getter used to flatten the claims into top level properties. Necessary to correctly serialize this object.
   */
  @JsonAnyGetter
  public Map<String, Object> anyGetter() {
    return claims;
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
    return claims.get(key);
  }

  public String getString(String key) {
    return (String) claims.get(key);
  }

  /**
   * Add a claim to this JWT. This claim can be public or private, it is up to the caller to properly name the
   * claim as to avoid collision.
   *
   * @param name  The name of the JWT claim.
   * @param value The value of the JWT claim. This value is an object and is expected to properly serialize.
   * @return this.
   */
  @JsonAnySetter
  public JWT withClaim(String name, Object value) {
    claims.put(name, value);
    return this;
  }

  public static class Builder {

    private JWT jwt;

    private Builder() {
      jwt = new JWT();
    }

    public Builder audience(Object audience) {
      jwt.audience = audience;
      return this;
    }

    public JWT build() {
      return jwt;
    }

    public Builder claim(String name, Object value) {
      jwt.withClaim(name, value);
      return this;
    }

    public Builder expiration(ZonedDateTime expiration) {
      jwt.expiration = expiration;
      return this;
    }

    public Builder issuedAt(ZonedDateTime issuedAt) {
      jwt.issuedAt = issuedAt;
      return this;
    }

    public Builder issuer(String issuer) {
      jwt.issuer = issuer;
      return this;
    }

    public Builder notBefore(ZonedDateTime notBefore) {
      jwt.notBefore = notBefore;
      return this;
    }

    public Builder subject(String subject) {
      jwt.subject = subject;
      return this;
    }

    public Builder uniqueId(String uniqueId) {
      jwt.uniqueId = uniqueId;
      return this;
    }
  }
}
