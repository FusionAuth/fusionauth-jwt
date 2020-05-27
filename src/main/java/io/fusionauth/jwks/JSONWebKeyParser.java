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
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

import static io.fusionauth.jwks.JWKUtils.base64DecodeUint;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeyParser {

  /**
   * Parse a JSON Web Key and extract the the public key.
   *
   * @param key the JSON web key
   * @return the public key
   */
  public PublicKey parse(JSONWebKey key) {
    Objects.requireNonNull(key);

    try {
      // RSA Public key
      if (key.alg == Algorithm.RS256 || key.alg == Algorithm.RS384 || key.alg == Algorithm.RS512) {
        BigInteger modulus = base64DecodeUint(key.n);
        BigInteger publicExponent = base64DecodeUint(key.e);
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      } else if (key.alg == Algorithm.ES256 || key.alg == Algorithm.ES384 || key.alg == Algorithm.ES512) {
        // EC Public key
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        switch (key.crv) {
          case "P-256":
            parameters.init(new ECGenParameterSpec("secp256r1"));
            break;
          case "P-384":
            parameters.init(new ECGenParameterSpec("secp384r1"));
            break;
          case "P-521":
            parameters.init(new ECGenParameterSpec("secp521r1"));
            break;
          default:
            throw new UnsupportedOperationException("Unsupported EC algorithm. Support algorithms include P-256, P-384 and P-521.");
        }

        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        BigInteger x = base64DecodeUint(key.x);
        BigInteger y = base64DecodeUint(key.y);
        ECPoint ecPoint = new ECPoint(x, y);
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));
      }
    } catch (Exception e) {
      throw new JSONWebKeyParserException("Failed to parse the provided JSON Web Key", e);
    }

    throw new UnsupportedOperationException("Only RSA or EC JSON Web Keys may be parsed.");
  }
}
