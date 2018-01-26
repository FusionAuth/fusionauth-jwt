/*
 * Copyright (c) 2016-2018, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt.hmac;

import org.primeframework.jwt.Verifier;
import org.primeframework.jwt.domain.Algorithm;
import org.primeframework.jwt.domain.InvalidJWTSignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class is used to verify a JWT signed with an HMAC algorithm.
 *
 * @author Daniel DeGroff
 */
public class HMACVerifier implements Verifier {

  private final byte[] secret;

  private HMACVerifier(String secret) {
    Objects.requireNonNull(secret);
    this.secret = secret.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param secret The secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(String secret) {
    return new HMACVerifier(secret);
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    switch (algorithm) {
      case HS256:
      case HS384:
      case HS512:
        return true;
      default:
        return false;
    }
  }

  @Override
  public void verify(Algorithm algorithm, byte[] payload, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(payload);
    Objects.requireNonNull(signature);

    try {
      Mac mac = Mac.getInstance(algorithm.getName());
      mac.init(new SecretKeySpec(secret, algorithm.getName()));
      byte[] actualSignature = mac.doFinal(payload);

      if (!Arrays.equals(signature, actualSignature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
