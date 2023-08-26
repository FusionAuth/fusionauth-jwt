/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwks;

import java.security.PublicKey;

import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.domain.KeyType;

/**
 * @author Daniel DeGroff
 */
public interface JSONWebKeyParser {
  /**
   * @return the key type that can be parsed by this parser.
   */
  KeyType keyType();

  /**
   * Parse a JSON Web Key and extract the public key.
   *
   * @param key the JSON web key
   * @return the public key
   */
  PublicKey parse(JSONWebKey key);
}
