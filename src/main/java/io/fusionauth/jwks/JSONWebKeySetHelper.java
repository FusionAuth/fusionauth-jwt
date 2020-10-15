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

package io.fusionauth.jwks;

import com.fasterxml.jackson.databind.JsonNode;
import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.json.Mapper;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeySetHelper {
  public static List<JSONWebKey> retrieveKeysFromIssuer(String endpoint) {
    Objects.requireNonNull(endpoint);
    if (endpoint.endsWith("/")) {
      endpoint = endpoint.substring(0, endpoint.length() - 1);
    }

    return retrieveKeysFromWellKnownConfiguration(endpoint + "/.well-known/openid-configuration");
  }

  private static <T> T get(String endpoint, Function<InputStream, T> consumer) {
    HttpURLConnection httpURLConnection;
    try {
      httpURLConnection = (HttpURLConnection) new URL(endpoint).openConnection();

      httpURLConnection.setDoOutput(true);
      httpURLConnection.setConnectTimeout(3_000);
      httpURLConnection.setReadTimeout(2_000);
      httpURLConnection.setRequestMethod("GET");

      httpURLConnection.addRequestProperty("User-Agent", "fusionauth-jwt (https://github.com/FusionAuth/fusionauth-jwt)");
      httpURLConnection.connect();
    } catch (Exception e) {
      throw new JSONWebKeySetException("Failed to connect to [" + endpoint + "].", e);
    }

    Connection connection = new Connection();
    connection.connection = httpURLConnection;

    try {
      connection.status = httpURLConnection.getResponseCode();
    } catch (Exception e) {
      throw new JSONWebKeySetException("Failed to make a request to [" + endpoint + "].", e);
    }

    if (connection.status < 200 || connection.status > 299) {
      throw new JSONWebKeySetException("Failed to make a request to [" + endpoint + "], a status code of [" + connection.status + "] was returned.");
    }

    try (InputStream is = new BufferedInputStream(connection.connection.getInputStream())) {
      return consumer.apply(is);
    } catch (Exception e) {
      throw new JSONWebKeySetException("Failed to parse the response as JSON from [" + endpoint + "].", e);
    }
  }

  public static List<JSONWebKey> retrieveKeysFromWellKnownConfiguration(String endpoint) {
    return get(endpoint, is -> {
      JsonNode response = Mapper.deserialize(is, JsonNode.class);
      JsonNode jwksURI = response.at("/jwks_uri");
      if (jwksURI.isMissingNode()) {
        throw new JSONWebKeySetException("The well-known endpoint [" + endpoint + "] has not defined a JSON Web Key Set endpoint. Missing the [jwks_uri] property.");
      }

      return retrieveKeysFromJWKS(jwksURI.asText());
    });
  }

  public static List<JSONWebKey> retrieveKeysFromJWKS(String endpoint) {
    return get(endpoint, is -> Mapper.deserialize(is, JSONWebKeySetResponse.class).keys);
  }

  private static class Connection {
    public int status;
    public HttpURLConnection connection;
  }

  public static class JSONWebKeySetException extends RuntimeException {
    public JSONWebKeySetException(String message) {
      super(message);
    }

    public JSONWebKeySetException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private static class JSONWebKeySetResponse {
    public List<JSONWebKey> keys;
  }
}
