/*
 * Copyright (c) 2022, FusionAuth, All Rights Reserved
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
package io.fusionauth.pem;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.fusionauth.jwt.MissingKeyDecoderException;
import io.fusionauth.jwt.ec.ECKeyDecoder;
import io.fusionauth.jwt.rsa.RSAKeyDecoder;

/**
 * @author Daniel DeGroff
 */
public class KeyDecoderFactory {
  private static final Map<String, KeyDecoder> KeyDecodersByKeyType = new HashMap<>();

  private static final Map<String, KeyDecoder> KeyDecodersByOID = new HashMap<>();

  private static final boolean[] registrationFinalized = new boolean[]{false};

  public static Set<String> allRegistered() {
    return new HashSet<>(KeyDecodersByOID.keySet());
  }

  /**
   * Note this is not Thread safe. If you need it to be thread-safe, you need to synchronize access.
   *
   * @param oid the object identifier
   */
  public static void deRegister(String oid) {
    ensureNotFinalized();
    KeyDecodersByOID.remove(oid);
    KeyDecodersByKeyType.remove(oid);
  }

  public static void finalizeRegistration() {
    registrationFinalized[0] = true;
  }

  // TODO : Rename: getInstanceByKeyType?
  public static KeyDecoder getByKeyType(String keyType) {
    Objects.requireNonNull(keyType);
    KeyDecoder keyDecoder = KeyDecodersByKeyType.get(keyType);
    if (keyDecoder == null) {
      throw new MissingKeyDecoderException("There are no Key Decoders registered for key type [" + keyType + "].");
    }

    return keyDecoder;
  }

  // TODO : Rename: getInstanceByOID?
  public static KeyDecoder getByOID(String oid) {
    Objects.requireNonNull(oid);
    KeyDecoder keyDecoder = KeyDecodersByOID.get(oid);
    if (keyDecoder == null) {
      throw new MissingKeyDecoderException("There are no Key Decoders registered for OID [" + oid + "].");
    }

    return keyDecoder;
  }

  /**
   * Note this is not Thread safe. If you need it to be thread-safe, you need to synchronize access.
   *
   * @param decoder the class type of the decoder
   */
  public static void register(Class<? extends KeyDecoder> decoder) {
    ensureNotFinalized();
    synchronized (KeyDecoderFactory.class) {
      try {
        KeyDecoder o = decoder.newInstance();
        KeyDecodersByOID.put(o.keyType().oid, o);
        KeyDecodersByKeyType.put(o.keyType().name, o);
      } catch (InstantiationException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
  }

  private static void ensureNotFinalized() {
    if (registrationFinalized[0]) {
      throw new IllegalStateException("Registration has been finalized. You may not modify the currently registered key decoders.");
    }
  }

  static {
    register(RSAKeyDecoder.class);
    register(ECKeyDecoder.class);
  }
}
