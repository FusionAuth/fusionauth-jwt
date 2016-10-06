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

import org.primeframework.jwt.domain.Algorithm;

/**
 * JWT Signer.
 *
 * @author Daniel DeGroff
 */
public abstract class Signer {

  public final Algorithm algorithm;

  protected Signer() {
    this.algorithm = Algorithm.none;
  }

  protected Signer(Algorithm algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Sign the provided message and return the signature.
   *
   * @param message The message to sign.
   * @return The message signature in a byte array.
   */
  abstract byte[] sign(String message);

  /**
   * Verify the signature of the encoded JWT.
   *
   * @param jwt The encoded JWT in the dot separated string format.
   * @return True if the JWT signature is successfully validated.
   */
  abstract boolean verify(String jwt);
}
