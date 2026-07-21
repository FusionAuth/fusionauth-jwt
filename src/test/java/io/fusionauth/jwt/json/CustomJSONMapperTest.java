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

import io.fusionauth.jwt.BaseJWTTest;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.fusionauth.jwt.hmac.HMACVerifier;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Verifies that a custom {@link JSONMapper} can be registered and is used end-to-end.
 */
public class CustomJSONMapperTest extends BaseJWTTest {
  @AfterMethod
  public void restoreDefaultMapper() {
    Mapper.resetMapper();
  }

  @Test
  public void customMapperIsUsedForSerializeAndDeserialize() {
    CountingJSONMapper counting = new CountingJSONMapper(new JacksonJSONMapper());
    Mapper.setMapper(counting);

    JWT jwt = new JWT()
        .setSubject("custom-mapper")
        .setExpiration(ZonedDateTime.of(2030, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC));

    byte[] bytes = Mapper.serialize(jwt);
    assertEquals(counting.serializeCalls.get(), 1);

    JWT roundTrip = Mapper.deserialize(bytes, JWT.class);
    assertEquals(counting.deserializeBytesCalls.get(), 1);
    assertEquals(roundTrip.subject, "custom-mapper");
    assertEquals(roundTrip.expiration, jwt.expiration);

    assertTrue(new String(Mapper.prettyPrint(jwt), StandardCharsets.UTF_8).contains("custom-mapper"));
    assertEquals(counting.prettyPrintCalls.get(), 1);
  }

  @Test
  public void customMapperUsedWhenEncodingAndDecodingJWT() {
    CountingJSONMapper counting = new CountingJSONMapper(new JacksonJSONMapper());
    Mapper.setMapper(counting);

    String encoded = JWT.getEncoder().encode(
        new JWT()
            .setSubject("encode-decode")
            .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
            .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5)),
        HMACSigner.newSHA256Signer("too many secrets"));

    assertTrue(counting.serializeCalls.get() >= 2, "header and payload should be serialized");

    JWT decoded = JWT.getDecoder().decode(encoded, HMACVerifier.newVerifier("too many secrets"));
    assertEquals(decoded.subject, "encode-decode");
    assertTrue(counting.deserializeBytesCalls.get() >= 2, "header and payload should be deserialized");
  }

  @Test
  public void resetMapperRestoresJacksonDefault() {
    CountingJSONMapper counting = new CountingJSONMapper(new JacksonJSONMapper());
    Mapper.setMapper(counting);
    assertEquals(Mapper.getMapper(), counting);

    Mapper.resetMapper();
    assertTrue(Mapper.getMapper() instanceof JacksonJSONMapper);
  }

  /**
   * Test double that counts invocations and delegates to a real mapper.
   */
  private static final class CountingJSONMapper implements JSONMapper {
    private final JSONMapper delegate;
    final AtomicInteger serializeCalls = new AtomicInteger();
    final AtomicInteger deserializeBytesCalls = new AtomicInteger();
    final AtomicInteger deserializeStreamCalls = new AtomicInteger();
    final AtomicInteger prettyPrintCalls = new AtomicInteger();

    CountingJSONMapper(JSONMapper delegate) {
      this.delegate = delegate;
    }

    @Override
    public <T> T deserialize(byte[] bytes, Class<T> type) {
      deserializeBytesCalls.incrementAndGet();
      return delegate.deserialize(bytes, type);
    }

    @Override
    public <T> T deserialize(InputStream is, Class<T> type) {
      deserializeStreamCalls.incrementAndGet();
      return delegate.deserialize(is, type);
    }

    @Override
    public byte[] prettyPrint(Object object) {
      prettyPrintCalls.incrementAndGet();
      return delegate.prettyPrint(object);
    }

    @Override
    public byte[] serialize(Object object) {
      serializeCalls.incrementAndGet();
      return delegate.serialize(object);
    }
  }
}
