/*
 * Copyright (c) 2026, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.json;

import io.fusionauth.jwt.InvalidJWTException;

import java.io.InputStream;

/**
 * Pluggable JSON serialize/deserialize SPI used by FusionAuth JWT.
 * <p>
 * The default implementation is {@link JacksonJSONMapper}. Register a custom
 * implementation with {@link Mapper#setMapper(JSONMapper)} if you prefer another
 * JSON library (for example Gson).
 * <p>
 * Implementations must correctly round-trip the library domain types used for
 * JWT headers, JWT payloads, JWKs, and OAuth2 metadata, including:
 * <ul>
 *   <li>Property renaming (e.g. {@code algorithm} ↔ {@code alg}, {@code uniqueId} ↔ {@code jti})</li>
 *   <li>Additional/unknown properties via the domain "any" maps</li>
 *   <li>{@link java.time.ZonedDateTime} claims as numeric UNIX epoch seconds</li>
 *   <li>Omitting null properties on serialize</li>
 * </ul>
 *
 * @author Daniel DeGroff
 * @see Mapper
 * @see JacksonJSONMapper
 */
public interface JSONMapper {
  /**
   * Deserialize JSON bytes into the given type.
   *
   * @param bytes the JSON bytes
   * @param type  the target type
   * @param <T>   the target type
   * @return the deserialized object
   * @throws InvalidJWTException if the JSON cannot be de-serialized
   */
  <T> T deserialize(byte[] bytes, Class<T> type) throws InvalidJWTException;

  /**
   * Deserialize a JSON input stream into the given type.
   *
   * @param is   the JSON input stream
   * @param type the target type
   * @param <T>  the target type
   * @return the deserialized object
   * @throws InvalidJWTException if the JSON cannot be de-serialized
   */
  <T> T deserialize(InputStream is, Class<T> type) throws InvalidJWTException;

  /**
   * Serialize an object to JSON with pretty printing.
   *
   * @param object the object to serialize
   * @return pretty-printed JSON bytes
   * @throws InvalidJWTException if the object cannot be serialized
   */
  byte[] prettyPrint(Object object) throws InvalidJWTException;

  /**
   * Serialize an object to compact JSON.
   *
   * @param object the object to serialize
   * @return JSON bytes
   * @throws InvalidJWTException if the object cannot be serialized
   */
  byte[] serialize(Object object) throws InvalidJWTException;
}
