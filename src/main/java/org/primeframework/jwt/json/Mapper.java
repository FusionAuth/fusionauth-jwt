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

package org.primeframework.jwt.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.primeframework.jwt.domain.InvalidJWTException;

import java.io.IOException;

/**
 * Serialize and de-serialize JWT header and payload.
 *
 * @author Daniel DeGroff
 */
public class Mapper {
  private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public static <T> T deserialize(byte[] bytes, Class<T> type) throws InvalidJWTException {
    try {
      return OBJECT_MAPPER.readValue(bytes, type);
    } catch (IOException e) {
      throw new InvalidJWTException("The JWT could not be de-serialized.", e);
    }
  }

  public static byte[] serialize(Object object) throws InvalidJWTException {
    try {
      return OBJECT_MAPPER.writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new InvalidJWTException("The JWT could not be serialized.", e);
    }
  }

  static {
    OBJECT_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .configure(SerializationFeature.WRITE_EMPTY_JSON_ARRAYS, false)
        .configure(SerializationFeature.WRITE_NULL_MAP_VALUES, false)
        .registerModule(new JacksonModule());
  }
}
