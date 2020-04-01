/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

package io.fusionauth.security;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * @author Daniel DeGroff
 */
public interface CryptoProvider {
  /**
   * Return an instance of a Mac digest for the provided algorithm name.
   *
   * @param algorithmName the name of the algorithm.
   * @return a Mac instance
   * @throws NoSuchAlgorithmException thrown when the requested algorithm cannot be satisfied by this crypto provider.
   */
  Mac getMacInstance(String algorithmName) throws NoSuchAlgorithmException;

  /**
   * Return an instance of a Signature digest for the provided algorithm name.
   *
   * @param algorithmName the name of the algorithm.
   * @return a Signature instance
   * @throws NoSuchAlgorithmException thrown when the requested algorithm cannot be satisfied by this crypto provider.
   */
  Signature getSignatureInstance(String algorithmName) throws NoSuchAlgorithmException;
}
