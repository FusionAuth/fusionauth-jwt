package io.fusionauth.http;

import io.fusionauth.jwks.JSONWebKeySetHelper;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * @author Daniel DeGroff
 */
public abstract class AbstractHttpHelper {
  protected static <T> T get(HttpURLConnection urlConnection, Function<InputStream, T> consumer, BiFunction<String, Throwable, ? extends RuntimeException> exception) {
    String endpoint = urlConnection.getURL().toString();

    try {
      urlConnection.setRequestMethod("GET");
      urlConnection.connect();
    } catch (Exception e) {
      throw exception.apply("Failed to connect to [" + endpoint + "].", e);
    }

    int status;
    try {
      status = urlConnection.getResponseCode();
    } catch (Exception e) {
      throw exception.apply("Failed to make a request to [" + endpoint + "].", e);
    }

    if (status < 200 || status > 299) {
      throw exception.apply("Failed to make a request to [" + endpoint + "], a status code of [" + status + "] was returned.", null);
    }

    try (InputStream is = new BufferedInputStream(urlConnection.getInputStream())) {
      return consumer.apply(is);
    } catch (Exception e) {
      throw exception.apply("Failed to parse the response as JSON from [" + endpoint + "].", e);
    }
  }

  protected static HttpURLConnection buildURLConnection(String endpoint) {
    try {
      HttpURLConnection urlConnection = (HttpURLConnection) new URL(endpoint).openConnection();
      urlConnection.setDoOutput(true);
      urlConnection.setConnectTimeout(10_000);
      urlConnection.setReadTimeout(10_000);
      urlConnection.addRequestProperty("User-Agent", "fusionauth-jwt (https://github.com/FusionAuth/fusionauth-jwt)");
      return urlConnection;
    } catch (IOException e) {
      throw new JSONWebKeySetHelper.JSONWebKeySetException("Failed to build connection to [" + endpoint + "].", e);
    }
  }
}
