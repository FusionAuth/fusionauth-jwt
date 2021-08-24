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

package io.fusionauth.jwt;

import java.time.ZonedDateTime;

/**
 * A version of the JWT Decoder that allows you to travel to the past or future by changing the space time continuum.
 *
 * @author Daniel DeGroff
 */
public class TimeMachineJWTDecoder extends JWTDecoder {
  private final ZonedDateTime now;

  public TimeMachineJWTDecoder(ZonedDateTime now) {
    this.now = now;
  }

  @Override
  protected ZonedDateTime now() {
    return now;
  }
}
