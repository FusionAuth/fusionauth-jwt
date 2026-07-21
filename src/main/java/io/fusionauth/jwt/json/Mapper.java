/*
 * Copyright (c) 2016-2026, FusionAuth, All Rights Reserved
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
import java.util.Objects;

/**
 * Serialize and de-serialize JWT header and payload (and other JSON types used by this library).
 * <p>
 * By default this facade delegates to {@link JacksonJSONMapper}. Applications that prefer a
 * different JSON library can register a custom {@link JSONMapper}:
 * <pre>
 *   Mapper.setMapper(new MyGsonJSONMapper());
 * </pre>
 * Call {@link #resetMapper()} to restore the default Jackson implementation.
 *
 * @author Daniel DeGroff
 * @see JSONMapper
 * @see JacksonJSONMapper
 */
public class Mapper {
  private static volatile JSONMapper mapper = new JacksonJSONMapper();

  /**
   * @return the currently configured {@link JSONMapper}
   */
  public static JSONMapper getMapper() {
    return mapper;
  }

  /**
   * Register a custom JSON mapper used for all subsequent serialize/deserialize operations.
   * This is a process-wide setting and is not scoped per JWT instance.
   *
   * @param jsonMapper the mapper implementation; must not be null
   */
  public static void setMapper(JSONMapper jsonMapper) {
    Objects.requireNonNull(jsonMapper, "jsonMapper");
    mapper = jsonMapper;
  }

  /**
   * Restore the default {@link JacksonJSONMapper}.
   */
  public static void resetMapper() {
    mapper = new JacksonJSONMapper();
  }

  public static <T> T deserialize(byte[] bytes, Class<T> type) throws InvalidJWTException {
    return mapper.deserialize(bytes, type);
  }

  public static <T> T deserialize(InputStream is, Class<T> type) throws InvalidJWTException {
    return mapper.deserialize(is, type);
  }

  public static byte[] prettyPrint(Object object) throws InvalidJWTException {
    return mapper.prettyPrint(object);
  }

  public static byte[] serialize(Object object) throws InvalidJWTException {
    return mapper.serialize(object);
  }
}
