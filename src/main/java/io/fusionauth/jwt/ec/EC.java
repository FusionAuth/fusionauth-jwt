/*
 * Copyright (c) 2023, FusionAuth, All Rights Reserved
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
package io.fusionauth.jwt.ec;

import io.fusionauth.jwt.domain.Algorithm;

/**
 * @author Daniel DeGroff
 */
public class EC {
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

  private EC() {
  }
}
