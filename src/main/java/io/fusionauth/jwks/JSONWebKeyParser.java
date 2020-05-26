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

package io.fusionauth.jwks;

import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.domain.Algorithm;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

import static io.fusionauth.jwks.JWKUtils.base64DecodeUint;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeyParser {

  public static PublicKey parse(JSONWebKey key) {
    Objects.requireNonNull(key);

    // RSA Public key
    if (key.alg == Algorithm.RS256 || key.alg == Algorithm.RS384 || key.alg == Algorithm.RS512) {
      try {
        BigInteger modulus = base64DecodeUint(key.n);
        BigInteger publicExponent = base64DecodeUint(key.e);
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      } catch (Exception e) {
        throw new JSONWebKeyParserException("Failed to parse the provided JSON Web Key", e);
      }
    }

    throw new UnsupportedOperationException("Only RSA JSON Web Keys may be parsed.");
  }
}
