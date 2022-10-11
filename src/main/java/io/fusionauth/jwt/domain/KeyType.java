/*
 * Copyright (c) 2016-2022, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwt.domain;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.jwt.UnsupportedKeyTypeException;
import io.fusionauth.jwt.UnsupportedObjectIdentifierException;

/**
 * Available Cryptographic Algorithms for Keys as described in <a href="https://tools.ietf.org/html/rfc7518#section-6.1">RFC
 * 7518 Section 6.1</a>.
 *
 * <ul> <li>ES Elliptic Curve [DDS]</li> <li>RSA as defined by  <a href="https://tools.ietf.org/html/rfc3447">RFC
 * 3447</a></li> <li>oct: Octet Sequence (used to represent symmetric keys)</li> </ul>
 * <p>
 * Currently only the RSA and EC Key Types is implemented and supported in this library.
 * </p>
 *
 * @author Daniel DeGroff
 */
public class KeyType {
  public static final KeyType EC = new KeyType("EC", "EC", ObjectIdentifier.EC_ENCRYPTION);

  public static final KeyType RSA = new KeyType("RSA", "RSA", ObjectIdentifier.RSA_ENCRYPTION);

  private static final Map<String, KeyType> KeyTypeByName = new HashMap<>();

  private static final Map<String, KeyType> KeyTypeByOID = new HashMap<>();

  private static final boolean[] registrationFinalized = new boolean[]{false};

  public final String algorithm;

  @JsonValue
  public final String name;

  public final String oid;

  public KeyType(String name, String algorithm, String oid) {
    this.name = name;
    this.algorithm = algorithm;
    this.oid = oid;
  }

  public static Set<String> allRegistered() {
    return new HashSet<>(KeyTypeByName.keySet());
  }

  /**
   * Note this is not Thread safe. If you need it to be thread-safe, you need to synchronize access.
   *
   * @param keyType the key type to de-register.
   */
  public static void deRegister(KeyType keyType) {
    ensureNotFinalized();
    KeyTypeByName.remove(keyType.name);
    KeyTypeByOID.remove(keyType.name);
  }

  public static void finalizeRegistration() {
    registrationFinalized[0] = true;
  }

  @JsonCreator
  public static KeyType lookupByName(String name) {
    Objects.requireNonNull(name);
    KeyType keyType = KeyTypeByName.get(name);
    if (keyType == null) {
      throw new UnsupportedKeyTypeException("No KeyType has been registered for type [" + name + "].");
    }

    return keyType;
  }

  // TODO : Do I need this?
  public static KeyType lookupByOID(String oid) {
    Objects.requireNonNull(oid);
    KeyType keyType = KeyTypeByOID.get(oid);
    if (keyType == null) {
      throw new UnsupportedObjectIdentifierException("No KeyType has been registered for OID [" + oid + "].");
    }

    return keyType;
  }

  /**
   * Note this is not Thread safe. If you need it to be thread-safe, you need to synchronize access.
   *
   * @param keyType the key type to register.
   */
  public static void register(KeyType keyType) {
    ensureNotFinalized();
    KeyTypeByName.put(keyType.name, keyType);
    KeyTypeByOID.put(keyType.oid, keyType);
  }

  private static void ensureNotFinalized() {
    if (registrationFinalized[0]) {
      throw new IllegalStateException("Registration has been finalized. You may not modify the currently registered key decoders.");
    }
  }

  static {
    register(KeyType.EC);
    register(KeyType.RSA);
  }
}
