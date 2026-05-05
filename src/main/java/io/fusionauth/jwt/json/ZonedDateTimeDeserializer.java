/*
 * Copyright (c) 2016, FusionAuth, All Rights Reserved
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

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdScalarDeserializer;

/**
 * Jackson de-serializer for the ZonedDateTime class.
 *
 * @author Daniel DeGroff
 */
public class ZonedDateTimeDeserializer extends StdScalarDeserializer<ZonedDateTime> {
  public ZonedDateTimeDeserializer() {
    super(Long.TYPE);
  }

  @Override
  public ZonedDateTime deserialize(JsonParser jp, DeserializationContext ctxt)  {
    JsonToken t = jp.currentToken();
    long value = -1;
    if (t == JsonToken.VALUE_NUMBER_INT || t == JsonToken.VALUE_NUMBER_FLOAT) {
      value = jp.getLongValue();
    } else if (t == JsonToken.VALUE_STRING) {
      String str = jp.getString().trim();
      if (str.length() == 0) {
        return null;
      }

      try {
        value = Long.parseLong(str);
      } catch (NumberFormatException e) {
        ctxt.reportInputMismatch(handledType(),"Invalid number");
      }
    } else {
      ctxt.reportInputMismatch(handledType(),"Invalid number");
    }

    return Instant.ofEpochSecond(value).atZone(ZoneOffset.UTC);
  }
}
