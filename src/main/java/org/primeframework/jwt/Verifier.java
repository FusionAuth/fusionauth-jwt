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
import org.primeframework.jwt.domain.MissingVerifierException;

/**
 * @author Daniel DeGroff
 */
public interface Verifier {
  /**
   * @param algorithm The algorithm required to verify the signature on this JWT.
   * @return True if this Verifier is able to verify a signature using the specified algorithm.
   */
  boolean canVerify(Algorithm algorithm);

  /**
   * Verify the signature of the encoded JWT payload.
   *
   * @param message   The JWT message. The header and claims, the first two segments of the dot separated JWT.
   * @param signature The signature to verify.
   * @throws MissingVerifierException If no Signer has been provided to verify the JWT signature.
   */
  void verify(Algorithm algorithm, byte[] message, byte[] signature);
}
