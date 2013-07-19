/*
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.plus.samples.quickstart;

import static spark.Spark.get;
import static spark.Spark.post;

import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Tokeninfo;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.PeopleFeed;
import com.google.gson.Gson;

import spark.Request;
import spark.Response;
import spark.Route;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Simple server to demonstrate how to use Google+ Sign-In and make a request
 * via your own server.
 *
 * @author vicfryzel@google.com (Vic Fryzel)
 */
public class Signin {
  /**
   * Replace this with the client ID you got from the Google APIs console.
   */
  private static final String CLIENT_ID = "YOUR_CLIENT_ID";
  /**
   * Replace this with the client secret you got from the Google APIs console.
   */
  private static final String CLIENT_SECRET = "YOUR_CLIENT_SECRET";
  /**
   * Optionally replace this with your application's name.
   */
  private static final String APPLICATION_NAME = "Google+ Java Quickstart";

  /**
   * Default HTTP transport to use to make HTTP requests.
   */
  private static final HttpTransport TRANSPORT = new NetHttpTransport();
  /**
   * Default JSON factory to use to deserialize JSON.
   */
  private static final JacksonFactory JSON_FACTORY = new JacksonFactory();
  /**
   * Gson object to serialize JSON responses to requests to this servlet.
   */
  private static final Gson GSON = new Gson();

  /**
   * Register all endpoints that we'll handle in our server.
   * @param args Command-line arguments.
   */
  public static void main(String[] args) {
    // Initialize a session for the current user, and render index.html.
    get(new Route("/") {
      @Override
      public Object handle(Request request, Response response) {
        response.type("text/html");
        try {
          // Create a state token to prevent request forgery.
          // Store it in the session for later validation.
          String state = new BigInteger(130, new SecureRandom()).toString(32);
          request.session().attribute("state", state);
          // Fancy way to read index.html into memory, and set the client ID
          // and state values in the HTML before serving it.
          return new Scanner(new File("index.html"), "UTF-8")
              .useDelimiter("\\A").next()
              .replaceAll("[{]{2}\\s*CLIENT_ID\\s*[}]{2}", CLIENT_ID)
              .replaceAll("[{]{2}\\s*STATE\\s*[}]{2}", state)
              .replaceAll("[{]{2}\\s*APPLICATION_NAME\\s*[}]{2}",
                  APPLICATION_NAME);
        } catch (FileNotFoundException e) {
          // When running the quickstart, there was some path issue in finding
          // index.html.  Double check the quickstart guide.
          e.printStackTrace();
          return e.toString();
        }
      }
    });
    // Upgrade given auth code to token, and store it in the session.
    // POST body of request should be the authorization code.
    // Example URI: /connect?state=...&gplus_id=...
    post(new Route("/connect") {
      @Override
      public Object handle(Request request, Response response) {
        response.type("application/json");
        // Only connect a user that is not already connected.
        String tokenData = request.session().attribute("token");
        if (tokenData != null) {
          response.status(200);
          return GSON.toJson("Current user is already connected.");
        }
        // Ensure that this is no request forgery going on, and that the user
        // sending us this connect request is the user that was supposed to.
        if (!request.queryParams("state").equals(
            request.session().attribute("state"))) {
          response.status(401);
          return GSON.toJson("Invalid state parameter.");
        }
        // Normally the state would be a one-time use token, however in our
        // simple case, we want a user to be able to connect and disconnect
        // without reloading the page.  Thus, for demonstration, we don't
        // implement this best practice.
        //request.session().removeAttribute("state");

        String code = request.body();

        try {
          // Upgrade the authorization code into an access and refresh token.
          GoogleTokenResponse tokenResponse =
              new GoogleAuthorizationCodeTokenRequest(TRANSPORT, JSON_FACTORY,
                  CLIENT_ID, CLIENT_SECRET, code, "postmessage").execute();

          // You can read the Google user ID in the ID token.
          // This sample does not use the user ID.
          GoogleIdToken idToken = tokenResponse.parseIdToken();
          String gplus_id = idToken.getPayload().getUserId();

          // Store the token in the session for later use.
          request.session().attribute("token", tokenResponse.toString());
          return GSON.toJson("Successfully connected user.");
        } catch (TokenResponseException e) {
          response.status(500);
          return GSON.toJson("Failed to upgrade the authorization code.");
        } catch (IOException e) {
          response.status(500);
          return GSON.toJson("Failed to read token data from Google. " +
              e.getMessage());
        }
      }
    });
    // Revoke current user's token and reset their session.
    post(new Route("/disconnect") {
      @Override
      public Object handle(Request request, Response response) {
        response.type("application/json");
        // Only disconnect a connected user.
        String tokenData = request.session().attribute("token");
        if (tokenData == null) {
          response.status(401);
          return GSON.toJson("Current user not connected.");
        }
        try {
          // Build credential from stored token data.
          GoogleCredential credential = new GoogleCredential.Builder()
              .setJsonFactory(JSON_FACTORY)
              .setTransport(TRANSPORT)
              .setClientSecrets(CLIENT_ID, CLIENT_SECRET).build()
              .setFromTokenResponse(JSON_FACTORY.fromString(
                  tokenData, GoogleTokenResponse.class));
          // Execute HTTP GET request to revoke current token.
          HttpResponse revokeResponse = TRANSPORT.createRequestFactory()
              .buildGetRequest(new GenericUrl(
                  String.format(
                      "https://accounts.google.com/o/oauth2/revoke?token=%s",
                      credential.getAccessToken()))).execute();
          // Reset the user's session.
          request.session().removeAttribute("token");
          return GSON.toJson("Successfully disconnected.");
        } catch (IOException e) {
          // For whatever reason, the given token was invalid.
          response.status(400);
          return GSON.toJson("Failed to revoke token for given user.");
        }
      }
    });
    // Get list of people user has shared with this app.
    get(new Route("/people") {
      @Override
      public Object handle(Request request, Response response) {
        response.type("application/json");
        // Only fetch a list of people for connected users.
        String tokenData = request.session().attribute("token");
        if (tokenData == null) {
          response.status(401);
          return GSON.toJson("Current user not connected.");
        }
        try {
          // Build credential from stored token data.
          GoogleCredential credential = new GoogleCredential.Builder()
              .setJsonFactory(JSON_FACTORY)
              .setTransport(TRANSPORT)
              .setClientSecrets(CLIENT_ID, CLIENT_SECRET).build()
              .setFromTokenResponse(JSON_FACTORY.fromString(
                  tokenData, GoogleTokenResponse.class));
          // Create a new authorized API client.
          Plus service = new Plus.Builder(TRANSPORT, JSON_FACTORY, credential)
              .setApplicationName(APPLICATION_NAME)
              .build();
          // Get a list of people that this user has shared with this app.
          PeopleFeed people = service.people().list("me", "visible").execute();
          return GSON.toJson(people);
        } catch (IOException e) {
          response.status(500);
          return GSON.toJson("Failed to read data from Google. " +
              e.getMessage());
        }
      }
    });
  }
}
