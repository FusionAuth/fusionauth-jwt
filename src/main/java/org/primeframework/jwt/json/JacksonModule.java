package org.primeframework.jwt.json;

import com.fasterxml.jackson.databind.module.SimpleModule;

import java.time.ZonedDateTime;

/**
 * @author Daniel DeGroff
 */
public class JacksonModule extends SimpleModule {
  public JacksonModule() {
    // Deserializers
    addDeserializer(ZonedDateTime.class, new ZonedDateTimeDeserializer());

    // Serializers
    addSerializer(ZonedDateTime.class, new ZonedDateTimeSerializer());
  }
}
