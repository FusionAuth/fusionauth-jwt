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
package io.fusionauth.jwks.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

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
public class RSAJSONWebKeyParser implements JSONWebKeyParser {
  @Override
  public KeyType keyType() {
    return KeyType.RSA;
  }

  @Override
  public PublicKey parse(JSONWebKey key) {
    try {
      BigInteger modulus = base64DecodeUint(key.n);
      BigInteger publicExponent = base64DecodeUint(key.e);
      PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

      // If an x5c is found in the key, verify the public key
      if (key.x5c != null && !key.x5c.isEmpty()) {
        verifyX5cRSA(key, modulus, publicExponent);
      }

      return publicKey;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void verifyX5cRSA(JSONWebKey key, BigInteger expectedModulus, BigInteger expectedPublicExponent) {
    // The first key in this array MUST contain the public key.
    // >  https://tools.ietf.org/html/rfc7517#section-4.7
    String encodedCertificate = key.x5c.get(0);
    String pem = new PEMEncoder().parseEncodedCertificate(encodedCertificate);
    PublicKey actual = PEM.decode(pem).publicKey;

    if (!(actual instanceof RSAPublicKey)) {
      throw new JSONWebKeyParserException("The public key found in the [x5c] property does not match the expected key type specified by the [kty] property.");
    }

    RSAPublicKey rsaPublicKey = (RSAPublicKey) actual;
    if (!rsaPublicKey.getModulus().equals(expectedModulus)) {
      throw new JSONWebKeyParserException("Expected a modulus value of [" + expectedModulus + "] but found [" + rsaPublicKey.getModulus() + "].  The certificate found in [x5c] does not match the [n] property.");
    }

    if (!rsaPublicKey.getPublicExponent().equals(expectedPublicExponent)) {
      throw new JSONWebKeyParserException("Expected a public exponent value of [" + expectedPublicExponent + "] but found [" + rsaPublicKey.getPublicExponent() + "].  The certificate found in [x5c] does not match the [e] property.");
    }
  }
}
