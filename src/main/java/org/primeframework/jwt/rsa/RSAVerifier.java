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

package org.primeframework.jwt.rsa;

import org.primeframework.jwt.Verifier;
import org.primeframework.jwt.domain.Algorithm;
import org.primeframework.jwt.domain.InvalidJWTSignatureException;
import org.primeframework.jwt.domain.InvalidKeyLengthException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * This class is used to verify a JWT with an RSA signature using an RSA Public Key.
 *
 * @author Daniel DeGroff
 */
public class RSAVerifier implements Verifier {

  private final RSAPublicKey publicKey;

  private RSAVerifier(String publicKey) {
    Objects.requireNonNull(publicKey);
    this.publicKey = RSAUtils.getPublicKeyFromPEM(publicKey);

    int keyLength = this.publicKey.getModulus().bitLength();
    if (keyLength < 2048) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public secret.
   *
   * @param publicKey The RSA public key PEM.
   * @return a new instance of the RSA verifier.
   */
  public static RSAVerifier newVerifier(String publicKey) {
    return new RSAVerifier(publicKey);
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    switch (algorithm) {
      case RS256:
      case RS384:
      case RS512:
        return true;
      default:
        return false;
    }
  }

  public void verify(Algorithm algorithm, byte[] payload, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(payload);
    Objects.requireNonNull(signature);

    try {
      Signature verifier = Signature.getInstance(algorithm.getName());
      verifier.initVerify(publicKey);
      verifier.update(payload);
      if (!verifier.verify(signature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new RuntimeException(e);
    }
  }
}
