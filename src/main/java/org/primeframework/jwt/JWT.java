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

package org.primeframework.jwt;

import org.primeframework.jwt.domain.Claims;
import org.primeframework.jwt.domain.Header;
import org.primeframework.jwt.domain.InvalidJWTException;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;


/**
 * @author Daniel DeGroff
 */
public class JWT {
  private final Claims claims = new Claims();

  private Header header = new Header();

  private Signer signer;

  /**
   * Registered Claim <code>iat</code> as defined by RFC 7519 Section 4.1.6. Use of this claim is OPTIONAL.
   *
   * @param issuedAt The issued at claim identifies the time at which the JWT was issued. The issued at time
   *                 is expected to provided in UNIX time, or the number of seconds since Epoch.
   * @return this.
   */
  public JWT IssuedAt(String issuedAt) {
    claims.put("iat", issuedAt);
    return this;
  }

  /**
   * Registered Claim <code>aud</code> as defined by RFC 7519 Section 4.1.3. Use of this claim is OPTIONAL.
   *
   * @param audience The subject claim identifies the principal that is the subject of the JWT.
   * @return this.
   */
  public JWT audience(Object audience) {
    claims.put("aud", audience);
    return this;
  }

  private String base64Encode(byte[] bytes) {
    return new String(Base64.getUrlEncoder().withoutPadding().encode(bytes));
  }

  /**
   * Add a claim to this JWT. This claim can be public or private, it is up to the caller to properly name the
   * claim as to avoid collision.
   *
   * @param name  The name of the JWT claim.
   * @param value The value of the JWT claim. This value is an object and is expected to properly serialize.
   * @return this.
   */
  public JWT claim(String name, Object value) {
    claims.put(name, value);
    return this;
  }

  /**
   * Registered Claim <code>exp</code> as defined by RFC 7519 Section 4.1.4. Use of this claim is OPTIONAL.
   *
   * @param expiration The expiration time claim identifies the expiration time on or after which the JWT MUST
   *                   NOT be accepted for processing. The expiration time is expected to provided in UNIX
   *                   time, or the number of seconds since Epoch.
   * @return this.
   */
  public JWT expiration(long expiration) {
    claims.put("exp", expiration);
    return this;
  }

  /**
   * Return the signed JWT in a dot separated encoded string suitable to be sent as an HTTP header.
   *
   * @return a dot separated encoded JWT.
   * @throws InvalidJWTException
   */
  public String get() throws InvalidJWTException {
    Objects.requireNonNull(signer);

    List<String> parts = new ArrayList<>(3);
    parts.add(base64Encode(Mapper.serialize(header)));
    parts.add(base64Encode(Mapper.serialize(claims)));

    byte[] signature = signer.sign(join(parts));
    parts.add(base64Encode(signature));

    return join(parts);
  }

  /**
   * Registered Claim <code>iss</code> as defined by RFC 7519 Section 4.1.1. Use of this claim is OPTIONAL.
   *
   * @param issuer The issuer claim identifies the principal that issued the JWT.
   * @return this.
   */
  public JWT issuer(String issuer) {
    claims.put("iss", issuer);
    return this;
  }

  private String join(Collection<String> collection) {
    return collection.stream().collect(Collectors.joining("."));
  }

  /**
   * Registered Claim <code>jti</code> as defined by RFC 7519 Section 4.1.7. Use of this claim is OPTIONAL.
   *
   * @param uniqueId The JWT unique ID claim provides a unique identifier for the JWT.
   * @return this.
   */
  public JWT jwtIdentifier(String uniqueId) {
    claims.put("jti", uniqueId);
    return this;
  }

  /**
   * Registered Claim <code>nbf</code> as defined by RFC 7519 Section 4.1.5. Use of this claim is OPTIONAL.
   *
   * @param notBefore The not before claim identifies the time before which the JWT MUST NOT be accepted for
   *                  processing. The not before value is expected to provided in UNIX time, or the number of
   *                  seconds since Epoch.
   * @return this.
   */
  public JWT notBefore(long notBefore) {
    claims.put("nbf", notBefore);
    return this;
  }

  /**
   * Registered Claim <code>sub</code> as defined by RFC 7519 Section 4.1.2. Use of this claim is OPTIONAL.
   *
   * @param subject The subject claim identifies the principal that is the subject of the JWT.
   * @return this.
   */
  public JWT subject(String subject) {
    claims.put("sub", subject);
    return this;
  }

  /**
   * Add the signer to this JWT. This is required to be added prior to calling {@link #get()} which will sign
   * the JWT.
   *
   * @param signer The signer.
   * @return this
   */
  public JWT withSigner(Signer signer) {
    Objects.requireNonNull(signer);
    Objects.requireNonNull(signer.algorithm);

    this.signer = signer;
    this.header.algorithm = signer.algorithm;
    return this;
  }
}
