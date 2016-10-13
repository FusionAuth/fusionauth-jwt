/*
 * Copyright (c) 2016, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt;

import org.primeframework.jwt.domain.Algorithm;
import org.primeframework.jwt.domain.Header;
import org.primeframework.jwt.domain.InvalidJWTException;
import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.domain.JWTExpiredException;
import org.primeframework.jwt.domain.JWTUnavailableForProcessingException;
import org.primeframework.jwt.domain.MissingVerifierException;
import org.primeframework.jwt.json.Mapper;

import java.util.Base64;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class JWTDecoder {

  private static JWTDecoder instance;

  public static JWTDecoder getInstance() {
    if (instance == null) {
      instance = new JWTDecoder();
    }

    return instance;
  }

  public JWT decode(String encodedJWT, Verifier... verifiers) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);

    String[] parts = encodedJWT.split("\\.");
    if (parts.length != 3) {
      throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
    }

    Header header = Mapper.deserialize(base64Decode(parts[0].getBytes()), Header.class);
    if (header.algorithm == Algorithm.none) {
      return Mapper.deserialize(base64Decode(parts[1].getBytes()), JWT.class);
    }

    Verifier verifier = null;
    for (Verifier v : verifiers) {
      if (v.canVerify(header.algorithm)) {
        verifier = v;
      }
    }

    if (verifier == null) {
      throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.algorithm.getName() + "]");
    }

    int index = encodedJWT.lastIndexOf(".");
    // The message comprises the first two segements of the entire JWT, the signature is the last segment.
    byte[] message = encodedJWT.substring(0, index).getBytes();
    byte[] signature = base64Decode(parts[2].getBytes());

    // Verify the signature before de-serializing the payload.
    verifier.verify(header.algorithm, message, signature);

    JWT jwt = Mapper.deserialize(base64Decode(parts[1].getBytes()), JWT.class);

    // Verify expiration claim
    if (jwt.isExpired()) {
      throw new JWTExpiredException();
    }

    // Verify the notBefore claim
    if (jwt.isUnavailableForProcessing()) {
      throw new JWTUnavailableForProcessingException();
    }

    return jwt;
  }

  private byte[] base64Decode(byte[] bytes) {
    return Base64.getUrlDecoder().decode(bytes);
  }
}
