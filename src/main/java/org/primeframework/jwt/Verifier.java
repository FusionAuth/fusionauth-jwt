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
import org.primeframework.jwt.domain.Claims;
import org.primeframework.jwt.domain.Header;
import org.primeframework.jwt.domain.InvalidJWTException;
import org.primeframework.jwt.domain.MissingSignerException;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * This class is used to verify a JWT. The provided <code>Signer</code> will perform the signature
 * verification.
 * <p>
 * Once a JWT has been verified the claims can be used to perform identity assertions.
 *
 * @author Daniel DeGroff
 */
public class Verifier {

  /**
   * One or more <code>Signer</code> objects keyed by their Algorithm that can be used to verify JWT
   * signatures.
   */
  private final Map<Algorithm, Signer> signers = new HashMap<>();

  /**
   * The decoded claims from the JWT payload. The claims should only be used if the <code>true</code> is
   * returned from the {@link #verify(String)} method.
   */
  public Claims claims;

  private byte[] base64Decode(byte[] bytes) {
    return Base64.getUrlDecoder().decode(bytes);
  }

  /**
   * Verify the provided JWT.
   *
   * @param encodedJwt The encoded dot separated JWT string.
   * @return True if the signature of the JWT is verified successfully.
   * @throws MissingSignerException If no Signer has been provided to verify the JWT signature.
   */
  public boolean verify(String encodedJwt) throws MissingSignerException, InvalidJWTException {
    Objects.requireNonNull(encodedJwt);

    String[] parts = encodedJwt.split("\\.");
    if (parts.length != 3) {
      throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
    }

    Header header = Mapper.deserialize(base64Decode(parts[0].getBytes()), Header.class);
    if (!signers.containsKey(header.algorithm)) {
      throw new MissingSignerException("No Signer has been provided for verify a signature signed using [" + header.algorithm.algorithmName + "]");
    }

    claims = Mapper.deserialize(base64Decode(parts[1].getBytes()), Claims.class);

    Signer signer = signers.get(header.algorithm);
    return signer.verify(encodedJwt);
  }

  /**
   * Add an additional signer to this verifier. If you add more than one signer for the same algorithm, the
   * last one will be used.
   *
   * @param signer The signer to add.
   * @return this.
   */
  public Verifier withSigner(Signer signer) {
    signers.put(signer.algorithm, signer);
    return this;
  }
}
