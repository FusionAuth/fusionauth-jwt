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

package io.fusionauth.http;


import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Daniel DeGroff
 */
public class BuilderHTTPHandler implements HttpHandler {
  public String actualRequestBody;

  public int called = 0;

  public Map<String, ExpectedResponse> responses;

  public BuilderHTTPHandler(Map<String, ExpectedResponse> responses) {
    this.responses = responses;
  }

  @Override
  public void handle(HttpExchange httpExchange) throws IOException {
    called++;

    try (BufferedReader reader = new BufferedReader(new InputStreamReader(httpExchange.getRequestBody(), StandardCharsets.UTF_8))) {
      actualRequestBody = reader.lines().collect(Collectors.joining(System.lineSeparator()));
    }

    String requestedURI = httpExchange.getRequestURI().toString();
    ExpectedResponse expectedResult = responses.get(requestedURI);

    // Bail right away if we have nothing to offer.
    if (expectedResult == null) {
      httpExchange.sendResponseHeaders(200, 0);
      httpExchange.getResponseBody().close();
      return;
    }

    // Else return the expected result
    byte[] bytes = expectedResult.response == null ? new byte[]{} : expectedResult.response.getBytes(StandardCharsets.UTF_8);
    httpExchange.sendResponseHeaders(expectedResult.status, bytes.length);

    if (bytes.length != 0) {
      httpExchange.getResponseBody().write(bytes);
      httpExchange.getResponseBody().flush();
    }

    if (expectedResult.contentType != null) {
      httpExchange.getResponseHeaders().add("Content-Type", expectedResult.contentType);
    }

    httpExchange.getResponseBody().close();
  }
}