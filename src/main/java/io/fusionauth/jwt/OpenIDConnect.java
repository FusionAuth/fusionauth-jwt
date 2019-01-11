/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt;

import io.fusionauth.jwt.domain.Algorithm;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Helpers for OpenID Connect.
 *
 * @author Daniel DeGroff
 */
public class OpenIDConnect {

  /**
   * Generate the hash of the Access Token specified by the OpenID Connect Core spec for the <code>at_hash</code> claim.
   *
   * @param accessToken the ASCII form of the access token
   * @param algorithm   the algorithm to be used when encoding the Id Token
   * @return a hash to be used as the <code>at_hash</code> claim in the Id Token claim payload
   * @throws NoSuchAlgorithmException Thrown when no provider supports an implementation of the specified algorithm
   */
  public static String at_hash(String accessToken, Algorithm algorithm) throws NoSuchAlgorithmException {
    return generate_hash(accessToken, algorithm, 128);
  }

  /**
   * Generate the hash of the Authorization Code as specified by the OpenID Connect Core spec for the <code>c_hash</code> claim.
   *
   * @param authorizationCode the ASCII form of the authorization code
   * @param algorithm         the algorithm to be used when encoding the Id Token
   * @return a hash to be used as the <code>c_hash</code> claim in the Id Token claim payload
   * @throws NoSuchAlgorithmException Thrown when no provider supports an implementation of the specified algorithm
   */
  public static String c_hash(String authorizationCode, Algorithm algorithm) throws NoSuchAlgorithmException {
    return generate_hash(authorizationCode, algorithm, 256);
  }

  private static String generate_hash(String string, Algorithm algorithm, int leftMostBits) throws NoSuchAlgorithmException {
    Objects.requireNonNull(string);
    Objects.requireNonNull(algorithm);
    if (leftMostBits % 8 != 0) {
      throw new IllegalArgumentException("The leftMostBits parameter is not valid. It must be a factor of 8.");
    }

    MessageDigest messageDigest;
    if (algorithm == Algorithm.RS256) {
      messageDigest = MessageDigest.getInstance("SHA-256");
    } else if (algorithm == Algorithm.RS384) {
      messageDigest = MessageDigest.getInstance("SHA-384");
    } else if (algorithm == Algorithm.RS512) {
      messageDigest = MessageDigest.getInstance("SHA-512");
    } else {
      throw new IllegalArgumentException("You specified an unsupported algorithm. The algorithm [" + algorithm + "]"
          + " is not supported. You must use RS256, RS384 or RS512.");
    }

    byte[] digest = string.getBytes(Charset.forName("UTF-8"));
    digest = messageDigest.digest(digest);

    int toIndex = Math.min(digest.length, leftMostBits / 8);
    byte[] leftMostBytes = Arrays.copyOfRange(digest, 0, toIndex);

    return new String(Base64.getUrlEncoder().withoutPadding().encode(leftMostBytes));
  }
}
