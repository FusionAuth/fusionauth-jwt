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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPublicKey;
import java.util.Objects;

import io.fusionauth.jwt.InvalidJWTSignatureException;
import io.fusionauth.jwt.InvalidKeyTypeException;
import io.fusionauth.jwt.JWTVerifierException;
import io.fusionauth.jwt.MissingPublicKeyException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.pem.domain.PEM;
import io.fusionauth.security.CryptoProvider;
import io.fusionauth.security.DefaultCryptoProvider;

public class EdDSAVerifier implements Verifier {
  private final CryptoProvider cryptoProvider;

  private final EdECPublicKey publicKey;

  private EdDSAVerifier(PublicKey publicKey, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(publicKey);
    Objects.requireNonNull(cryptoProvider);

    this.cryptoProvider = cryptoProvider;
    if (!(publicKey instanceof EdECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [EdECPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = (EdECPublicKey) publicKey;
  }

  private EdDSAVerifier(String publicKey, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(publicKey);
    Objects.requireNonNull(cryptoProvider);

    this.cryptoProvider = cryptoProvider;
    PEM pem = PEM.decode(publicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }

    if (!(pem.publicKey instanceof EdECPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a private key of type [EdECPublicKey], but found [" + pem.privateKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = pem.getPublicKey();
  }

  public static EdDSAVerifier newVerifier(Path path) {
    return newVerifier(path, new DefaultCryptoProvider());
  }

  public static EdDSAVerifier newVerifier(Path path, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(path);

    try {
      return new EdDSAVerifier(new String(Files.readAllBytes(path)), cryptoProvider);
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return algorithm == Algorithm.EdDSA;
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Signature verifier = cryptoProvider.getSignatureInstance(algorithm.getName());
      verifier.initVerify(publicKey);
      verifier.update(message);

      if (!(verifier.verify(signature))) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
