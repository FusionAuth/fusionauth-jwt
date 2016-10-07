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
public interface Signer {

  /**
   * Return the algorithm supported by this signer.
   *
   * @return the algorithm.
   */
  Algorithm getAlgorithm();

  /**
   * Sign the provided message and return the signature.
   *
   * @param payload The JWT payload to sign.
   * @return The message signature in a byte array.
   */
  byte[] sign(String payload);
}
