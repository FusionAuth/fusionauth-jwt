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
package io.fusionauth.jwt.rsa;

import io.fusionauth.jwt.domain.Algorithm;

/**
 * @author Daniel DeGroff
 */
public class RSA {

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

  private RSA() {

  }
}
