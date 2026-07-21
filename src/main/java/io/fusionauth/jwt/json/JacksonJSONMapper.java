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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.fusionauth.jwt.InvalidJWTException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Default {@link JSONMapper} backed by Jackson.
 *
 * @author Daniel DeGroff
 */
public class JacksonJSONMapper implements JSONMapper {
  private final ObjectMapper objectMapper;

  /**
   * Create a mapper with the default FusionAuth Jackson configuration.
   */
  public JacksonJSONMapper() {
    this(createDefaultObjectMapper());
  }

  /**
   * Create a mapper that uses a provided Jackson {@link ObjectMapper}.
   * The mapper is not copied; callers should not reconfigure it after construction
   * if it may be used concurrently.
   *
   * @param objectMapper the Jackson object mapper to use
   */
  public JacksonJSONMapper(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  /**
   * @return a new ObjectMapper configured the way FusionAuth JWT expects.
   */
  public static ObjectMapper createDefaultObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .configure(SerializationFeature.WRITE_NULL_MAP_VALUES, false)
        .configure(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS, true)
        .configure(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS, true)
        .registerModule(new JacksonModule());
    return mapper;
  }

  @Override
  public <T> T deserialize(byte[] bytes, Class<T> type) throws InvalidJWTException {
    try {
      return objectMapper.readValue(bytes, type);
    } catch (IOException e) {
      throw new InvalidJWTException("The JWT could not be de-serialized.", e);
    }
  }

  @Override
  public <T> T deserialize(InputStream is, Class<T> type) throws InvalidJWTException {
    try {
      return objectMapper.readValue(is, type);
    } catch (IOException e) {
      throw new InvalidJWTException("The input stream could not be de-serialized.", e);
    }
  }

  @Override
  public byte[] prettyPrint(Object object) throws InvalidJWTException {
    try {
      return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new InvalidJWTException("The object could not be serialized.", e);
    }
  }

  @Override
  public byte[] serialize(Object object) throws InvalidJWTException {
    try {
      return objectMapper.writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new InvalidJWTException("The JWT could not be serialized.", e);
    }
  }
}
