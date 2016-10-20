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

import org.primeframework.jwt.domain.Header;
import org.primeframework.jwt.domain.JWT;
import org.primeframework.jwt.json.Mapper;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author Daniel DeGroff
 */
public class JWTEncoder {

  private static JWTEncoder instance;

  public static JWTEncoder getInstance() {
    if (instance == null) {
      instance = new JWTEncoder();
    }

    return instance;
  }

  /**
   * Encode the JWT to produce a dot separated encoded string that can be sent in an HTTP request header.
   *
   * @param jwt    The JWT.
   * @param signer The signer used to add a signature to the JWT.
   * @return the encoded JWT string.
   */
  public String encode(JWT jwt, Signer signer) {
    return encode(jwt, signer, null);
  }

  /**
   * Encode the JWT to produce a dot separated encoded string that can be sent in an HTTP request header.
   *
   * @param jwt      The JWT.
   * @param signer   The signer used to add a signature to the JWT.
   * @param consumer A header consumer to optionally add header values to the encoded JWT. May be null.
   * @return the encoded JWT string.
   */
  public String encode(JWT jwt, Signer signer, Consumer<Header> consumer) {
    Objects.requireNonNull(jwt);
    Objects.requireNonNull(signer);

    List<String> parts = new ArrayList<>(3);
    Header header = new Header();
    if (consumer != null) {
      consumer.accept(header);
    }
    // Set this after we pass the header to the consumer to ensure it isn't tampered with.
    header.algorithm = signer.getAlgorithm();
    parts.add(base64Encode(Mapper.serialize(header)));
    parts.add(base64Encode(Mapper.serialize(jwt)));

    byte[] signature = signer.sign(join(parts));
    parts.add(base64Encode(signature));

    return join(parts);
  }

  private String base64Encode(byte[] bytes) {
    return new String(Base64.getUrlEncoder().withoutPadding().encode(bytes));
  }

  private String join(Collection<String> collection) {
    return collection.stream().collect(Collectors.joining("."));
  }
}
