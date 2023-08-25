/*
 * Copyright (c) 2016-2023, FusionAuth, All Rights Reserved
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

import java.util.Objects;
import java.util.ServiceLoader;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.fusionauth.jwt.SafeServiceLoader;
import io.fusionauth.jwt.UnsupportedAlgorithmException;
import io.fusionauth.jwt.spi.AlgorithmProvider;

/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 */
public class Algorithm {
  private static final ServiceLoader<AlgorithmProvider> loader = SafeServiceLoader.load(AlgorithmProvider.class);

  @JsonValue
  public final String name;

  public final Integer saltLength;

  public final String value;

  public Algorithm(String name, String value) {
    this(name, value, null);
  }

  public Algorithm(String name, String value, Integer saltLength) {
    this.name = name;
    this.value = value;
    this.saltLength = saltLength;
  }

  @JsonCreator
  public static Algorithm lookupByName(String name) {
    Objects.requireNonNull(name);
    for (AlgorithmProvider provider : loader) {
      Algorithm algorithm = provider.get();
      if (algorithm.name.equals(name)) {
        return algorithm;
      }
    }

    throw new UnsupportedAlgorithmException("Unknown algorithm name [" + name + "].");
  }

  public static Algorithm lookupByValue(String value) {
    Objects.requireNonNull(value);
    for (AlgorithmProvider provider : loader) {
      Algorithm algorithm = provider.get();
      if (algorithm.value.equals(value)) {
        return algorithm;
      }
    }

    throw new UnsupportedAlgorithmException("Unknown algorithm value [" + value + "].");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Algorithm algorithm = (Algorithm) o;
    return Objects.equals(value, algorithm.value) && Objects.equals(saltLength, algorithm.saltLength) && Objects.equals(name, algorithm.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(value, saltLength, name);
  }
}
