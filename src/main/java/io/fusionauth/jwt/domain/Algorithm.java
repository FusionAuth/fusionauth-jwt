/*
 * Copyright (c) 2016-2022, FusionAuth, All Rights Reserved
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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.fusionauth.jwt.UnsupportedAlgorithmException;

/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 */
public class Algorithm {

  private static final Map<String, Algorithm> AlgorithmsByName = new HashMap<>();

  private static final Map<String, Algorithm> AlgorithmsByValue = new HashMap<>();

  private static final boolean[] registrationFinalized = new boolean[]{false};

  /**
   * ECDSA using P-256 and SHA-256
   * OID: 1.2.840.10045.3.1.7
   * - prime256v1 / secp256r1
   */
  public static Algorithm ES256 = new Algorithm("ES256", "SHA256withECDSA");

  /**
   * ECDSA using P-384 and SHA-384
   * OID: 1.3.132.0.34
   * - secp384r1 / secp384r1
   */
  public static Algorithm ES384 = new Algorithm("ES384", "SHA384withECDSA");

  /**
   * ECDSA using P-521 and SHA-512
   * OID: 1.3.132.0.35
   * - prime521v1 / secp521r1
   */
  public static Algorithm ES512 = new Algorithm("ES512", "SHA512withECDSA");

  /**
   * HMAC using SHA-256
   */
  public static Algorithm HS256 = new Algorithm("HS256", "HmacSHA256");

  /**
   * HMAC using SHA-384
   */
  public static Algorithm HS384 = new Algorithm("HS384", "HmacSHA384");

  /**
   * HMAC using SHA-512
   */
  public static Algorithm HS512 = new Algorithm("HS512", "HmacSHA512");

  /**
   * RSASSA-PSS using SHA-256 and MGF1 with SHA-256
   * - SHA256withRSAandMGF1
   */
  public static Algorithm PS256 = new Algorithm("PS256", "SHA-256", 32);

  /**
   * RSASSA-PSS using SHA-384 and MGF1 with SHA-384
   * - SHA384withRSAandMGF1
   */
  public static Algorithm PS384 = new Algorithm("PS384", "SHA-384", 48);

  /**
   * RSASSA-PSS using SHA-512 and MGF1 with SHA-512
   * - SHA512withRSAandMGF1
   */
  public static Algorithm PS512 = new Algorithm("PS512", "SHA-512", 64);

  /**
   * RSASSA-PKCS1-v1_5 using SHA-256
   */
  public static Algorithm RS256 = new Algorithm("RS256", "SHA256withRSA");

  /**
   * RSASSA-PKCS1-v1_5 using SHA-384
   */
  public static Algorithm RS384 = new Algorithm("RS384", "SHA384withRSA");

  /**
   * RSASSA-PKCS1-v1_5 using SHA-512
   */
  public static Algorithm RS512 = new Algorithm("RS512", "SHA512withRSA");

  /**
   * No digital signature or MAC performed.
   */
  public static Algorithm none = new Algorithm("none", "None");

  @JsonValue
  public final String name;

  public final Integer saltLength;

  public final String value;

  public Algorithm(String name, String value) {
    this(name, value, null);
  }

  public Algorithm(String name, String value, Integer saltLength) {
    this.name = name;
    this.value = value;
    this.saltLength = saltLength;
  }

  public static Set<String> allRegistered() {
    return new HashSet<>(AlgorithmsByName.keySet());
  }

  /**
   * Note this is not Thread safe. If you need it to be thread-safe, you need to synchronize access.
   *
   * @param algorithm the algorithm to de-register.
   */
  public static void deRegister(Algorithm algorithm) {
    ensureNotFinalized();
    AlgorithmsByName.remove(algorithm.name);
    AlgorithmsByValue.remove(algorithm.value);
  }

  public static void finalizeRegistration() {
    registrationFinalized[0] = true;
  }

  @JsonCreator
  public static Algorithm lookupByName(String name) {
    Objects.requireNonNull(name);
    Algorithm algorithm = AlgorithmsByName.get(name);
    if (algorithm == null) {
      throw new UnsupportedAlgorithmException("Unknown algorithm name [" + name + "].");
    }

    return algorithm;
  }

  public static Algorithm lookupByValue(String value) {
    Objects.requireNonNull(value);
    Algorithm algorithm = AlgorithmsByValue.get(value);
    if (algorithm == null) {
      throw new UnsupportedAlgorithmException("Unknown algorithm value [" + value + "].");
    }

    return algorithm;
  }

  /**
   * Note this is not Thread safe. If you need it to be thread-safe, you need to synchronize access.
   *
   * @param algorithm the algorithm to register.
   */
  public static void register(Algorithm algorithm) {
    ensureNotFinalized();
    AlgorithmsByName.put(algorithm.name, algorithm);
    AlgorithmsByValue.put(algorithm.value, algorithm);
  }

  private static void ensureNotFinalized() {
    if (registrationFinalized[0]) {
      throw new IllegalStateException("Registration has been finalized. You may not modify the currently registered algorithms.");
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Algorithm algorithm = (Algorithm) o;
    return Objects.equals(value, algorithm.value) && Objects.equals(saltLength, algorithm.saltLength) && Objects.equals(name, algorithm.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(value, saltLength, name);
  }

  static {
    register(ES256);
    register(ES384);
    register(ES512);

    register(HS256);
    register(HS384);
    register(HS512);

    register(PS256);
    register(PS384);
    register(PS512);

    register(RS256);
    register(RS384);
    register(RS512);
  }
}
