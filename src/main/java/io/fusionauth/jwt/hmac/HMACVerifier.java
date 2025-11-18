/*
 * Copyright (c) 2016-2025, FusionAuth, All Rights Reserved
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

import io.fusionauth.jwt.InvalidJWTSignatureException;
import io.fusionauth.jwt.JWTVerifierException;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.Algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

  private HMACVerifier(byte[] secret) {
    Objects.requireNonNull(secret);
    this.secret = secret;
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param secret The secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(String secret) {
    Objects.requireNonNull(secret);
    return new HMACVerifier(secret);
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param path The path to the secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(Path path) {
    Objects.requireNonNull(path);

    try {
      return new HMACVerifier(Files.readAllBytes(path));
    } catch (IOException e) {
      throw new JWTVerifierException("Unable to read the file from path [" + path.toAbsolutePath() + "]", e);
    }
  }

  /**
   * Return a new instance of the HMAC Verifier with the provided secret.
   *
   * @param bytes The bytes of the secret.
   * @return a new instance of the HMAC verifier.
   */
  public static HMACVerifier newVerifier(byte[] bytes) {
    Objects.requireNonNull(bytes);
    return new HMACVerifier(bytes);
  }

  @Override
  @SuppressWarnings("Duplicates")
  public boolean canVerify(Algorithm algorithm) {
    return switch (algorithm) {
      case HS256, HS384, HS512 -> true;
      default -> false;
    };
  }

  @Override
  public void verify(Algorithm algorithm, byte[] message, byte[] signature) {
    Objects.requireNonNull(algorithm);
    Objects.requireNonNull(message);
    Objects.requireNonNull(signature);

    try {
      Mac mac = Mac.getInstance(algorithm.getName());
      mac.init(new SecretKeySpec(secret, algorithm.getName()));
      byte[] actualSignature = mac.doFinal(message);

      if (!MessageDigest.isEqual(signature, actualSignature)) {
        throw new InvalidJWTSignatureException();
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JWTVerifierException("An unexpected exception occurred when attempting to verify the JWT", e);
    }
  }
}
