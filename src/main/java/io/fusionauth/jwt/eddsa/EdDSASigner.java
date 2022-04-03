/*
 * Copyright (c) 2022, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.eddsa;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.util.Objects;

import io.fusionauth.jwt.InvalidKeyTypeException;
import io.fusionauth.jwt.JWTSigningException;
import io.fusionauth.jwt.MissingPrivateKeyException;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.pem.domain.PEM;
import io.fusionauth.security.CryptoProvider;
import io.fusionauth.security.DefaultCryptoProvider;

/**
 * @author Daniel DeGroff
 */
public class EdDSASigner implements Signer {
  private final Algorithm algorithm;

  private final CryptoProvider cryptoProvider;

  private final String kid;

  private final EdECPrivateKey privateKey;

  private EdDSASigner(Algorithm algorithm, PrivateKey privateKey, String kid, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(cryptoProvider);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.cryptoProvider = cryptoProvider;
    this.kid = kid;

    if (!(privateKey instanceof EdECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [EdECPrivateKey], but found [" + privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = (EdECPrivateKey) privateKey;
  }

  private EdDSASigner(Algorithm algorithm, String privateKey, String kid, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(cryptoProvider);
    Objects.requireNonNull(privateKey);

    this.algorithm = algorithm;
    this.cryptoProvider = cryptoProvider;
    this.kid = kid;
    PEM pem = PEM.decode(privateKey);
    if (pem.privateKey == null) {
      throw new MissingPrivateKeyException("The provided PEM encoded string did not contain a private key.");
    }

    if (!(pem.privateKey instanceof EdECPrivateKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [EdECPrivateKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }

    this.privateKey = pem.getPrivateKey();
  }

  public static EdDSASigner newSigner(String privateKey) {
    return new EdDSASigner(Algorithm.EdDSA, privateKey, null, new DefaultCryptoProvider());
  }

  @Override
  public Algorithm getAlgorithm() {
    return Algorithm.EdDSA;
  }

  @Override
  public String getKid() {
    return kid;
  }

  @Override
  public byte[] sign(String message) {
    Objects.requireNonNull(message);

    try {
      // In later versions of the JDK you can request a non DER encoded signature so we don't have to re-encode it.
      // - We could revisit this in the future if we want to depend on a later version of Java.
      //   To request the version we want, you can append "inP1363Format" to the algorithm name.
      //   Example : ES256inP1363Format instead of ES256.
      Signature signature = cryptoProvider.getSignatureInstance(algorithm.getName());
      signature.initSign(privateKey);
      signature.update((message).getBytes(StandardCharsets.UTF_8));
      byte[] derEncoded = signature.sign();

      return derEncoded;
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JWTSigningException("An unexpected exception occurred when attempting to sign the JWT", e);
    }
  }
}
