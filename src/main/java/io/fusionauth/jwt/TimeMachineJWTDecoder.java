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
