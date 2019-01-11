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

/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 */
public enum Algorithm {
  /**
   * ECDSA using P-256 and SHA-256
   * OID: 1.2.840.10045.3.1.7
   *  - prime256v1 / secp256r1
   */
  ES256("SHA256withECDSA"),

  /**
   * ECDSA using P-384 and SHA-384
   * OID: 1.3.132.0.34
   *  - secp384r1 / secp384r1
   */
  ES384("SHA384withECDSA"),

  /**
   * ECDSA using P-521 and SHA-512
   * OID: 1.3.132.0.35
   *  - prime521v1 / secp521r1
   */
  ES512("SHA512withECDSA"),

  /**
   * HMAC using SHA-256
   */
  HS256("HmacSHA256"),

  /**
   * HMAC using SHA-384
   */
  HS384("HmacSHA384"),

  /**
   * HMAC using SHA-512
   */
  HS512("HmacSHA512"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-256
   */
  RS256("SHA256withRSA"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-384
   */
  RS384("SHA384withRSA"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-512
   */
  RS512("SHA512withRSA"),

  /**
   * No digital signature or MAC performed.
   */
  none("None");

  public String algorithm;

  Algorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  public static Algorithm fromName(String name) {
    for (Algorithm alg : Algorithm.values()) {
      if (alg.getName().equals(name)) {
        return alg;
      }
    }

    return null;
  }

  public String getName() {
    return algorithm;
  }
}
