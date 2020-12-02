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

package io.fusionauth.oauth2;

import io.fusionauth.http.AbstractHttpHelper;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.oauth2.domain.AuthorizationServerMetaData;

import java.net.HttpURLConnection;
import java.util.Objects;

/**
 * @author Daniel DeGroff
 */
public class ServerMetaDataHelper extends AbstractHttpHelper {
  /**
   * Retrieve OAuth2 Authorization Server Metadata using the issuer as a starting point.
   *
   * @param issuer the issuer used to resolve the Authorization Server Metadata document.
   * @return the authorization server meta data.
   */
  public static AuthorizationServerMetaData retrieveFromIssuer(String issuer) {
    Objects.requireNonNull(issuer);
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    return retrieveFromWellKnownConfiguration(issuer + "/.well-known/oauth-authorization-server");
  }

  /**
   * Retrieve OAuth2 Authorization Server Metadata. Use this method if you know the well-known meta data URL and you want to build your own HTTP URL Connection.
   *
   * @param httpURLConnection the HTTP URL Connection that will be used to connect to the Authorization Server Metadata well known discovery endpoint.
   * @return the authorization server metadata.
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(HttpURLConnection httpURLConnection) {
    return get(httpURLConnection,
        is -> Mapper.deserialize(is, AuthorizationServerMetaData.class),
        ServerMetaDataException::new);
  }

  /**
   * Retrieve OAuth2 Authorization Server Metadata. Use this method if you know the well-known meta data URL.
   *
   * @param endpoint the Authorization Metadata well known discovery endpoint.
   * @return the authorization server metadata.
   */
  public static AuthorizationServerMetaData retrieveFromWellKnownConfiguration(String endpoint) {
    return retrieveFromWellKnownConfiguration(buildURLConnection(endpoint));
  }

  public static class ServerMetaDataException extends RuntimeException {
    public ServerMetaDataException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
