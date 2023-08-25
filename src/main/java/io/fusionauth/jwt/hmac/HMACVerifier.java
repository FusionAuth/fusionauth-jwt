/*
 * Copyright (c) 2016-2022, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import io.fusionauth.jwt.InvalidJWTSignatureException;
import io.fusionauth.jwt.JWTVerifierException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.security.CryptoProvider;
import io.fusionauth.security.DefaultCryptoProvider;

/**
 * This class is used to verify a JWT signed with an HMAC algorithm.
 *
 * @author Daniel DeGroff
 */
public class HMACVerifier implements Verifier {
  private final Set<Algorithm> SupportedAlgorithms = new HashSet<>(Arrays.asList(
      HMAC.HS256,
      HMAC.HS384,
      HMAC.HS512
  ));

  private final CryptoProvider cryptoProvider;

  private final byte[] secret;

  private HMACVerifier(String secret, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(secret);
    Objects.requireNonNull(cryptoProvider);

    this.cryptoProvider = cryptoProvider;
    this.secret = secret.getBytes(StandardCharsets.UTF_8);
  }

  private HMACVerifier(byte[] secret, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(secret);
    Objects.requireNonNull(cryptoProvider);

    this.cryptoProvider = cryptoProvider;
    this.secret = secret;
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param secret The secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(String secret) {
    return newVerifier(secret, new DefaultCryptoProvider());
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param path The path to the secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(Path path) {
    return newVerifier(path, new DefaultCryptoProvider());
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param bytes The bytes of the secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(byte[] bytes) {
    return newVerifier(bytes, new DefaultCryptoProvider());
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param secret         The secret.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(String secret, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(secret);
    return new HMACVerifier(secret, cryptoProvider);
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param path           The path to the secret.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(Path path, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(path);

    try {
      return new HMACVerifier(Files.readAllBytes(path), cryptoProvider);
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param bytes          The bytes of the secret.
   * @param cryptoProvider The crypto provider used to get the MAC digest algorithm.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(byte[] bytes, CryptoProvider cryptoProvider) {
    Objects.requireNonNull(bytes);
    return new HMACVerifier(bytes, cryptoProvider);
  }

  @Override
  public boolean canVerify(Algorithm algorithm) {
    return SupportedAlgorithms.contains(algorithm);
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Mac mac = cryptoProvider.getMacInstance(algorithm.value);
      mac.init(new SecretKeySpec(secret, algorithm.value));
      byte[] actualSignature = mac.doFinal(message);

      if (!MessageDigest.isEqual(signature, actualSignature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
