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

import io.fusionauth.jwks.JSONWebKeySetHelper;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * @author Daniel DeGroff
 */
public abstract class AbstractHttpHelper {

	private static volatile HttpClient HTTP_CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(10000)).build();

	public static void setHttpClient(HttpClient client) {
		HTTP_CLIENT = client;
	}

	protected static <T> T get(HttpRequest request, Function<InputStream, T> consumer,
			BiFunction<String, Throwable, ? extends RuntimeException> exception) {
		String endpoint = request.uri().toString();

		HttpResponse<InputStream> response;
		try {
			response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofInputStream());
		} catch (Exception e) {
			throw exception.apply("Failed to make a request to [" + endpoint + "].", e);
		}

		int status = response.statusCode();
		if (status < 200 || status > 299) {
			throw exception.apply(
					"Failed to make a request to [" + endpoint + "], a status code of [" + status + "] was returned.",
					null);
		}

		try (InputStream is = response.body()) {
			return consumer.apply(is);
		} catch (Exception e) {
			throw exception.apply("Failed to parse the response as JSON from [" + endpoint + "].", e);
		}
	}

	protected static HttpRequest buildRequest(String endpoint, Consumer<HttpRequest.Builder> consumer) {
	    try {
	    	HttpRequest.Builder builder = HttpRequest.newBuilder()
	    		.uri(URI.create(endpoint))
	    		.timeout(Duration.ofMillis(10_000))
	    		.header("User-Agent", "fusionauth-jwt (https://github.com/FusionAuth/fusionauth-jwt)")
	    		.GET();

	    	if (consumer != null) {
	    		consumer.accept(builder);
	    	}

	    	return builder.build();
	    } catch (Exception e) {
	        throw new JSONWebKeySetHelper.JSONWebKeySetException(
	        	"Failed to build connection to [" + endpoint + "].", e);
	    }
	}	
	
}
