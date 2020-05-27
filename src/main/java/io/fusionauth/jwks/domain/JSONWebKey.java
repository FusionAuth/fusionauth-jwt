/*
 * Copyright (c) 2017-2019, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwks.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.fusionauth.jwks.JSONWebKeyBuilder;
import io.fusionauth.jwks.JSONWebKeyBuilderException;
import io.fusionauth.jwks.JSONWebKeyParser;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.Buildable;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.json.Mapper;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 JSON Web Key (JWK)
 * Section 4</a> and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518 JSON Web Algorithms (JWA)</a>.
 *
 * @author Daniel DeGroff
 */
public class JSONWebKey implements Buildable<JSONWebKey> {
  /**
   * The "alg" parameter identifies the algorithm intended for use with this key.
   */
  public Algorithm alg;

  /**
   * The name of the Elliptic curve.
   * <ul>
   * <li>P-256</li>
   * <li>P-384</li>
   * <li>P-521</li>
   * </ul>
   */
  public String crv;

  /**
   * The "d" parameter contains the private exponent value for the RSA private key as described in RFC 7518 Section 6.3.2.1
   * It is represented as a Base64urlUInt-encoded value.
   * <p>
   * The "d" parameter contains the private key for an ECC Private Key as described in RFC 7518 Section 6.2.2.1
   */
  public String d;

  /**
   * The "dp" parameter contains the first factor CRT (Chinese Remainder Theorem) exponent factor for the RSA private
   * key.  It is represented as a Base64urlUInt-encoded value.
   */
  public String dp;

  /**
   * The "dq" parameter contains the second factor CRT (Chinese Remainder Theorem) exponent factor for the RSA private
   * key.  It is represented as a Base64urlUInt-encoded value.
   */
  public String dq;

  /**
   * The "e" parameter contains the public exponent value for the RSA public key.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  public String e;

  /**
   * The key identifier. This value can be used to match up the correct key to verify a JWT signature based upon the 'kid'
   * found in the JWT header.
   */
  public String kid;

  /**
   * The key type parameter.
   * <ul>
   * <li>EC : Elliptic Curve</li>
   * <li>RSA : RSA</li>
   * <li>oct : Octet sequence (used to represent symmetric keys)</li>
   * </ul>
   */
  public KeyType kty;

  /**
   * The "n" parameter contains the modulus value for the RSA public key.  It is represented as a Base64urlUInt-encoded value.
   */
  public String n;

  /**
   * This Map will contain all the properties that aren't specifically defined in this class.
   */
  @JsonAnySetter
  public Map<String, Object> other = new LinkedHashMap<>();

  /**
   * The "p" parameter contains the first prime factor for the RSA private key.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  public String p;

  /**
   * The "q" parameter contains the second prime factor for the RSA private key.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  public String q;

  /**
   * The "qi" parameter contains the first CRT (Chinese Remainder Theorem) coefficient factor for the RSA private key.
   * It is represented as a Base64urlUInt-encoded value.
   */
  public String qi;

  /**
   * The "use" parameter identifies the intended use of the public key.
   * <ul>
   * <li>sig : signature</li>
   * <li>enc : encryption</li>
   * </ul>
   */
  public String use;

  /**
   * The "x" parameter is the x coordinate of the Elliptic Curve
   */
  public String x;

  /**
   * The "x5c" parameter contains the encoded X509 certificate chain.
   */
  public List<String> x5c;

  /**
   * The x.509 SHA-1 certificate thumbprint.
   */
  public String x5t;

  /**
   * The x.509 SHA-256 certificate thumbprint.
   */
  @JsonProperty("x5t#S256")
  public String x5t_256;

  /**
   * The "y" parameter is the y coordinate of the Elliptic Curve
   */
  public String y;

  /**
   * Build a JSON Web Key from an encoded PEM.
   *
   * @param encodedPEM an encoded PEM
   * @return a JSON Web Key
   */
  public static JSONWebKey build(String encodedPEM) {
    return new JSONWebKeyBuilder().build(encodedPEM);
  }

  /**
   * Build a public key from a JSON Web Key containing a public RSA or EC key.
   *
   * @param key a JSON web key containing a public key
   * @return a public key
   */
  public static PublicKey parse(JSONWebKey key) {
    return new JSONWebKeyParser().parse(key);
  }

  /**
   * Build a JSON Web Key from a certificate
   *
   * @param certificate the certificate
   * @return a JSON Web Key
   */
  public static JSONWebKey build(Certificate certificate) {
    return new JSONWebKeyBuilder().build(certificate);
  }

  /**
   * Build a JSON Web Key from a private key
   *
   * @param privateKey a private key
   * @return a JSON Web Key
   */
  public static JSONWebKey build(PrivateKey privateKey) {
    return new JSONWebKeyBuilder().build(privateKey);
  }

  /**
   * Build a JSON Web Key from a public key
   *
   * @param publicKey a public key
   * @return a JSON Web Key
   */
  public static JSONWebKey build(PublicKey publicKey) {
    return new JSONWebKeyBuilder().build(publicKey);
  }

  @JsonIgnore
  public JSONWebKey add(String key, Object value) {
    if (key == null || value == null) {
      return this;
    }

    switch (key) {
      case "alg":
      case "crv":
      case "d":
      case "dp":
      case "dq":
      case "e":
      case "kid":
      case "kty":
      case "n":
      case "p":
      case "q":
      case "qi":
      case "use":
      case "x":
      case "x5c":
      case "x5t":
      case "x5t_256":
      case "y":
        throw new JSONWebKeyBuilderException("You can not add a named property. Use the field for [" + key + "] instead.", new IllegalArgumentException());
      default:
        other.put(key, value);
    }

    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof JSONWebKey)) return false;
    JSONWebKey that = (JSONWebKey) o;
    return alg == that.alg &&
        Objects.equals(crv, that.crv) &&
        Objects.equals(d, that.d) &&
        Objects.equals(dp, that.dp) &&
        Objects.equals(dq, that.dq) &&
        Objects.equals(e, that.e) &&
        Objects.equals(kid, that.kid) &&
        kty == that.kty &&
        Objects.equals(n, that.n) &&
        Objects.equals(p, that.p) &&
        Objects.equals(q, that.q) &&
        Objects.equals(qi, that.qi) &&
        Objects.equals(use, that.use) &&
        Objects.equals(x, that.x) &&
        Objects.equals(x5c, that.x5c) &&
        Objects.equals(x5t, that.x5t) &&
        Objects.equals(x5t_256, that.x5t_256) &&
        Objects.equals(y, that.y);
  }

  @JsonAnyGetter
  public Map<String, Object> getOther() {
    return other;
  }

  @Override
  public int hashCode() {
    return Objects.hash(alg, crv, d, dp, dq, e, kid, kty, n, p, q, qi, use, x, x5c, x5t, x5t_256, y);
  }

  public String toJSON() {
    return new String(Mapper.serialize(this));
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }
}
