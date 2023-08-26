/*
 * Copyright (c) 2023, FusionAuth, All Rights Reserved
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
package io.fusionauth.jwt.ec;

import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.ec.EC;
import io.fusionauth.jwt.spi.AlgorithmProvider;

/**
 * @author Daniel DeGroff
 */
public class ES256AlgorithmProvider implements AlgorithmProvider {
  @Override
  public Algorithm get() {
    return EC.ES256;
  }
}
