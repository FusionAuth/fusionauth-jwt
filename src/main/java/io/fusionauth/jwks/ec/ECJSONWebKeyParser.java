/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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
package io.fusionauth.jwks.ec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import io.fusionauth.jwks.JSONWebKeyParser;
import io.fusionauth.jwks.JSONWebKeyParserException;
import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.PEMEncoder;
import io.fusionauth.pem.domain.PEM;
import static io.fusionauth.jwks.JWKUtils.base64DecodeUint;

/**
 * @author Daniel DeGroff
 */
public class ECJSONWebKeyParser implements JSONWebKeyParser {
  @Override
  public KeyType keyType() {
    return KeyType.EC;
  }

  @Override
  public PublicKey parse(JSONWebKey key) {
    try {
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
      BigInteger xCoordinate = base64DecodeUint(key.x);
      BigInteger yCoordinate = base64DecodeUint(key.y);
      ECPoint ecPoint = new ECPoint(xCoordinate, yCoordinate);
      PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));

      // If an x5c is found in the key, verify the public key
      if (key.x5c != null && key.x5c.size() > 0) {
        verifyX5cEC(key, xCoordinate, yCoordinate);
      }

      return publicKey;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void verifyX5cEC(JSONWebKey key, BigInteger expectedXCoordinate, BigInteger expectedYCoordinate) {
    // The first key in this array MUST contain the public key.
    // >  https://tools.ietf.org/html/rfc7517#section-4.7
    String encodedCertificate = key.x5c.get(0);
    String pem = new PEMEncoder().parseEncodedCertificate(encodedCertificate);
    PublicKey actual = PEM.decode(pem).publicKey;
    if (!(actual instanceof ECPublicKey)) {
      throw new JSONWebKeyParserException("The public key found in the [x5c] property does not match the expected key type specified by the [kty] property.");
    }

    ECPublicKey ecPublicKey = (ECPublicKey) actual;
    ECPoint point = ecPublicKey.getW();

    if (!point.getAffineX().equals(expectedXCoordinate)) {
      throw new JSONWebKeyParserException("Expected an x coordinate value of [" + expectedXCoordinate + "] but found [" + point.getAffineX() + "].  The certificate found in [x5c] does not match the [x] coordinate property.");
    }

    //noinspection SuspiciousNameCombination
    if (!point.getAffineY().equals(expectedYCoordinate)) {
      throw new JSONWebKeyParserException("Expected a y coordinate value of [" + expectedYCoordinate + "] but found [" + point.getAffineY() + "].  The certificate found in [x5c] does not match the [y] coordinate property.");
    }
  }
}
