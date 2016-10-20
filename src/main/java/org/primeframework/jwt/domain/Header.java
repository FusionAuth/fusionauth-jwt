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

package org.primeframework.jwt.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON Object Signing and Encryption (JOSE) Header
 *
 * @author Daniel DeGroff
 */
public class Header {
  @JsonProperty("alg")
  public Algorithm algorithm;

  @JsonIgnore
  public Map<String, String> properties = new LinkedHashMap<>();

  @JsonProperty("typ")
  public Type type = Type.JWT;

  public Header() {
  }

  public Header(Algorithm algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Special getter used to flatten additional header properties into top level values. Necessary to correctly serialize
   * this object.
   */
  @JsonAnyGetter
  public Map<String, String> anyGetter() {
    return properties;
  }

  public String get(String name) {
    return properties.get(name);
  }

  /**
   * Add a property to the JWT header.
   *
   * @param name  The name of the header property.
   * @param value The value of the header property.
   * @return this.
   */
  @JsonAnySetter
  public Header set(String name, String value) {
    properties.put(name, value);
    return this;
  }
}
