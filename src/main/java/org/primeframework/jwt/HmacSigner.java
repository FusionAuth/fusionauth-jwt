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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * This class can sign and verify a JWT that was signed using HMAC. An instance of this class is intended to be re-used with the {@link Verifier}.
 *
 * @author Daniel DeGroff
 */
public class HmacSigner extends Signer {

  private byte[] secret;

  public HmacSigner(Algorithm algorithm) {
    super(algorithm);
  }

  @Override
  public byte[] sign(String message) {
    Objects.requireNonNull(secret);

    try {
      Mac mac = Mac.getInstance(algorithm.algorithmName);
      mac.init(new SecretKeySpec(secret, algorithm.algorithmName));
      return mac.doFinal(message.getBytes());
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verify(String jwt) {
    Objects.requireNonNull(jwt);

    int index = jwt.lastIndexOf(".");
    byte[] message = jwt.substring(0, index).getBytes();
    byte[] jwtSignature = Base64.getUrlDecoder().decode(jwt.substring(index + 1));

    Objects.requireNonNull(secret);

    try {
      Mac mac = Mac.getInstance(algorithm.algorithmName);
      mac.init(new SecretKeySpec(secret, algorithm.algorithmName));
      byte[] actualSignature = mac.doFinal(message);

      return Arrays.equals(jwtSignature, actualSignature);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public HmacSigner withSecret(String secret) {
    this.secret = secret.getBytes();
    return this;
  }
}
