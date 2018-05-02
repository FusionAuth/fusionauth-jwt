/*
 * Copyright (c) 2016-2018, Inversoft Inc., All Rights Reserved
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
import org.primeframework.jwt.domain.InvalidJWTSignatureException;
import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.domain.JWTExpiredException;
import org.primeframework.jwt.domain.JWTUnavailableForProcessingException;
import org.primeframework.jwt.domain.MissingVerifierException;
import org.primeframework.jwt.json.Mapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

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

  /**
   * Decode the JWT using one of they provided verifiers. One more verifiers may be provided, the first verifier found
   * supporting the algorithm reported by the JWT header will be utilized.
   * <p>
   * A JWT that is expired or not yet valid will not be decoded, instead a {@link JWTExpiredException} or {@link
   * JWTUnavailableForProcessingException} exception will be thrown respectively.
   *
   * @param encodedJWT The encoded JWT in string format.
   * @param verifiers  A map of verifiers.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Verifier... verifiers) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);

    // An unsecured JWT will not contain a signature and should only have a header and a payload.
    String[] parts = getParts(encodedJWT);
    Header header = Mapper.deserialize(base64Decode(parts[0].getBytes(StandardCharsets.UTF_8)), Header.class);

    // If parts.length == 2 we have no signature, if no verifiers were provided, decode if header says 'none', else throw an exception
    if (parts.length == 2 && verifiers.length == 0) {
      if (header.algorithm == Algorithm.none) {
        return Mapper.deserialize(base64Decode(parts[1].getBytes(StandardCharsets.UTF_8)), JWT.class);
      } else {
        throw new InvalidJWTSignatureException();
      }
    }

    // If verifiers were provided, ensure it is able to verify this JWT.
    Verifier verifier = null;
    for (Verifier v : verifiers) {
      if (v.canVerify(header.algorithm)) {
        verifier = v;
      }
    }

    return decode(encodedJWT, header, parts, verifier);
  }

  /**
   * Decode the JWT using one of they provided verifiers. A JWT header value named <code>kid</code> is expected to
   * contain the key to lookup the correct verifier.
   * <p>
   * A JWT that is expired or not yet valid will not be decoded, instead a {@link JWTExpiredException} or {@link
   * JWTUnavailableForProcessingException} exception will be thrown respectively.
   *
   * @param encodedJWT The encoded JWT in string format.
   * @param verifiers  A map of verifiers.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers) {
    return decode(encodedJWT, verifiers, h -> h.get("kid"));
  }

  /**
   * Decode the JWT using one of they provided verifiers. The key used to lookup the correct verifier is provided by the
   * <code>keyFunction</code>. The key function is provided the JWT header and is expected to return a string key to
   * look up the correct verifier.
   * <p>
   * A JWT that is expired or not yet valid will not be decoded, instead a {@link JWTExpiredException} or {@link
   * JWTUnavailableForProcessingException} exception will be thrown respectively.
   *
   * @param encodedJWT  The encoded JWT in string format.
   * @param verifiers   A map of verifiers.
   * @param keyFunction A function used to lookup the verifier key from the header.
   * @return a decoded JWT.
   */
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers, Function<Header, String> keyFunction) {
    Objects.requireNonNull(encodedJWT);
    Objects.requireNonNull(verifiers);
    Objects.requireNonNull(keyFunction);

    String[] parts = getParts(encodedJWT);
    Header header = Mapper.deserialize(base64Decode(parts[0].getBytes(StandardCharsets.UTF_8)), Header.class);
    // If parts.length == 2 we have no signature, if no verifiers were provided, decode if header says 'none', else throw an exception
    if (parts.length == 2 && verifiers.isEmpty()) {
      if (header.algorithm == Algorithm.none) {
        return Mapper.deserialize(base64Decode(parts[1].getBytes(StandardCharsets.UTF_8)), JWT.class);
      } else {
        throw new InvalidJWTSignatureException();
      }
    }

    // If verifiers were provided, ensure it is able to verify this JWT.
    String key = keyFunction.apply(header);
    Verifier verifier = verifiers.get(key);
    if (verifier != null) {
      if (!verifier.canVerify(header.algorithm)) {
        verifier = null;
      }
    }

    return decode(encodedJWT, header, parts, verifier);
  }

  private byte[] base64Decode(byte[] bytes) {
    try {
      return Base64.getUrlDecoder().decode(bytes);
    } catch (IllegalArgumentException e) {
      throw new InvalidJWTException("The encoded JWT is not properly Base64 encoded.", e);
    }
  }

  private JWT decode(String encodedJWT, Header header, String[] parts, Verifier verifier) {
    // The callers of this decode will have already handled 'none' if it was deemed to be valid based upon
    // the provided verifiers. At this point, if we have a 'none' algorithm specified in the header, it is invalid.
    if (header.algorithm == Algorithm.none) {
      throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.algorithm.getName() + "]");
    }

    // If a signature is provided and verifier must be provided.
    if (parts.length == 3 && verifier == null) {
      throw new MissingVerifierException("No Verifier has been provided for verify a signature signed using [" + header.algorithm.getName() + "]");
    }

    // A verifier was provided but no signature exists, this is treated as an invalid signature.
    if (parts.length == 2 && verifier != null) {
      throw new InvalidJWTSignatureException();
    }

    int index = encodedJWT.lastIndexOf(".");
    // The message comprises the first two segments of the entire JWT, the signature is the last segment.
    byte[] message = encodedJWT.substring(0, index).getBytes(StandardCharsets.UTF_8);

    if (parts.length == 3) {
      // Verify the signature before de-serializing the payload.
      byte[] signature = base64Decode(parts[2].getBytes(StandardCharsets.UTF_8));
      verifier.verify(header.algorithm, message, signature);
    }

    JWT jwt = Mapper.deserialize(base64Decode(parts[1].getBytes(StandardCharsets.UTF_8)), JWT.class);

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

  private String[] getParts(String encodedJWT) {
    String[] parts = encodedJWT.split("\\.");
    // Secured JWT XXXXX.YYYYY.ZZZZZ, Unsecured JWT XXXXX.YYYYY.
    if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
      return parts;
    }

    throw new InvalidJWTException("The encoded JWT is not properly formatted. Expected a three part dot separated string.");
  }
}
