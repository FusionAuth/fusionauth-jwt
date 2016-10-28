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

/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 */
public enum Algorithm {
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

  public String getName() {
    return algorithm;
  }
}
