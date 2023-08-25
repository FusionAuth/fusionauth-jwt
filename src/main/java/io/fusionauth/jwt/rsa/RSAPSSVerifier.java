/*
 * Copyright (c) 2020-2022, FusionAuth, All Rights Reserved
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import io.fusionauth.jwt.InvalidJWTSignatureException;
import io.fusionauth.jwt.InvalidKeyLengthException;
import io.fusionauth.jwt.InvalidKeyTypeException;
import io.fusionauth.jwt.JWTVerifierException;
import io.fusionauth.jwt.MissingPublicKeyException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.pem.domain.PEM;
import io.fusionauth.security.CryptoProvider;
import io.fusionauth.security.DefaultCryptoProvider;

/**
 * This class is used to verify a JWT with an RSA PSA signature using an RSA Public Key.
 *
 * @author Daniel DeGroff
 */
public class RSAPSSVerifier implements Verifier {
  private final Set<Algorithm> SupportedAlgorithms = new HashSet<>(Arrays.asList(
      RSA.PS256,
      RSA.PS384,
      RSA.PS512
  ));

  private final CryptoProvider cryptoProvider;

  private final RSAPublicKey publicKey;

  private RSAPSSVerifier(PublicKey publicKey, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(publicKey);
    Objects.requireNonNull(cryptoProvider);

    this.cryptoProvider = cryptoProvider;
    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + publicKey.getClass().getSimpleName() + "].");
    }
    this.publicKey = (RSAPublicKey) publicKey;
    assertValidKeyLength();
  }

  private RSAPSSVerifier(String publicKey, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(publicKey);
    Objects.requireNonNull(cryptoProvider);

    this.cryptoProvider = cryptoProvider;
    PEM pem = PEM.decode(publicKey);
    if (pem.publicKey == null) {
      throw new MissingPublicKeyException("The provided PEM encoded string did not contain a public key.");
    }
    if (!(pem.publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyTypeException("Expecting a public key of type [RSAPublicKey], but found [" + pem.publicKey.getClass().getSimpleName() + "].");
    }

    this.publicKey = pem.getPublicKey();
    assertValidKeyLength();
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param publicKey The RSA public key object.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(PublicKey publicKey) {
    return new RSAPSSVerifier(publicKey, new DefaultCryptoProvider());
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param publicKey      The RSA public key object.
   * @param cryptoProvider The crypto provider used to get the RSA signature Algorithm.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(PublicKey publicKey, CryptoProvider cryptoProvider) {
    return new RSAPSSVerifier(publicKey, cryptoProvider);
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param publicKey The RSA public key PEM.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(String publicKey) {
    return new RSAPSSVerifier(publicKey, new DefaultCryptoProvider());
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param publicKey      The RSA public key PEM.
   * @param cryptoProvider The crypto provider used to get the RSA signature Algorithm.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(String publicKey, CryptoProvider cryptoProvider) {
    return new RSAPSSVerifier(publicKey, cryptoProvider);
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param path The path to the RSA public key PEM.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(Path path) {
    return newVerifier(path, new DefaultCryptoProvider());
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param path           The path to the RSA public key PEM.
   * @param cryptoProvider The crypto provider used to get the RSA signature Algorithm.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(Path path, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(path);

    try {
      return new RSAPSSVerifier(new String(Files.readAllBytes(path)), cryptoProvider);
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath().toString() + "]", e);
    }
  }

  /**
   * Return a new instance of the RSA Verifier with the provided public key.
   *
   * @param bytes The bytes of the RSA public key PEM.
   * @return a new instance of the RSA verifier.
   */
  public static RSAPSSVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new RSAPSSVerifier((new String(bytes)), new DefaultCryptoProvider());
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return SupportedAlgorithms.contains(algorithm);
  }

  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Signature verifier = cryptoProvider.getSignatureInstance("RSASSA-PSS");
      verifier.setParameter(new PSSParameterSpec(algorithm.value, "MGF1", new MGF1ParameterSpec(algorithm.value), algorithm.saltLength, 1));
      verifier.initVerify(publicKey);
      verifier.update(message);
      if (!verifier.verify(signature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | SecurityException |
             InvalidAlgorithmParameterException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }

  private void assertValidKeyLength() {
    int keyLength = this.publicKey.getModulus().bitLength();
    if (keyLength < 2048) {
      throw new InvalidKeyLengthException("Key length of [" + keyLength + "] is less than the required key length of 2048 bits.");
    }
  }
}
