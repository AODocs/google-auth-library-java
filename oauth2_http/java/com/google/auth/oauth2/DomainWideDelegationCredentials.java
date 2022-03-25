/*
 * Copyright 2018, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static com.google.common.base.MoreObjects.firstNonNull;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.ExponentialBackOff;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Joiner;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * DomainWideDelegationCredentials allowing to obtain credentials for a user of a Workspace domain that has
 * granted domain-wide delegation to a service account.
 * The source project using DomainWideDelegationCredentials must enable the "IAMCredentials" API.
 * Also, the target service account must grant the originating principal the "iam.serviceAccounts.signJwt" IAM permission
 * (which is included in the "Service Account Token Creator" default IAM role).
 *
 * <p>Usage:
 *
 * <pre>
 * //could use GoogleCredentials.getApplicationDefault()
 * String credPath = "/path/to/svc_account.json";
 * ServiceAccountCredentials sourceCredentials = ServiceAccountCredentials
 *     .fromStream(new FileInputStream(credPath));
 * sourceCredentials = (ServiceAccountCredentials) sourceCredentials
 *     .createScoped(Arrays.asList("https://www.googleapis.com/auth/iam"));
 *
 * DomainWideDelegationCredentials dwdCredentials = DomainWideDelegationCredentials.create(sourceCredentials,
 *     "dwd-enabled-service-account@project.iam.gserviceaccount.com",
 *     null,
 *     "target-user@workspacedomain.com"
 *     Arrays.asList("https://www.googleapis.com/auth/drive"));
 *
 * File file = new Drive(
 * 		Utils.getDefaultTransport(),
 * 		Utils.getDefaultJsonFactory(),
 * 		new HttpCredentialsAdapter(dwdCredentials))
 * 		.files().get("FILE_ID").execute();
 * </pre>
 */
public class DomainWideDelegationCredentials extends GoogleCredentials
    implements QuotaProjectIdProvider {

  private static final long serialVersionUID = -2133257318957488431L;
  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  private static final int DEFAULT_LIFETIME_IN_SECONDS = 3600;
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final int DEFAULT_NUMBER_OF_RETRIES = 3;
  private static final int INITIAL_RETRY_INTERVAL_MILLIS = 1000;
  private static final double RETRY_RANDOMIZATION_FACTOR = 0.1;
  private static final double RETRY_MULTIPLIER = 2;
  private static final String CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final String IAM_SIGN_JWT_ENDPOINT =
          "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:signJwt";

  private GoogleCredentials sourceCredentials;
  private final String serviceAccountEmail;
  private final String userEmail;
  private final List<String> delegates;
  private final List<String> scopes;
  private final String quotaProjectId;
  private final boolean defaultRetriesEnabled;
  private final String transportFactoryClassName;

  private transient HttpTransportFactory transportFactory;

  /**
   * @param sourceCredentials the source credential used to acquire the DwD credentials. It
   *     should be either a user account credential or a service account credential.
   * @param serviceAccountEmail the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If unset, sourceCredential must have that role on
   *     serviceAccountEmail.
   * @param userEmail the email of the user to obtain credentials for
   * @param scopes scopes to request during the authorization grant
   * @param transportFactory HTTP transport factory that creates the transport used to get access
   *     tokens
   * @return new credentials
   */
  public static DomainWideDelegationCredentials create(
      GoogleCredentials sourceCredentials,
      String serviceAccountEmail,
      List<String> delegates,
      String userEmail,
      List<String> scopes,
      HttpTransportFactory transportFactory) {
    return DomainWideDelegationCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setServiceAccountEmail(serviceAccountEmail)
        .setDelegates(delegates)
        .setUserEmail(userEmail)
        .setScopes(scopes)
        .setHttpTransportFactory(transportFactory)
        .build();
  }

  /**
   * @param sourceCredentials the source credential used to acquire the impersonated credentials. It
   *     should be either a user account credential or a service account credential.
   * @param serviceAccountEmail the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If unset, sourceCredential must have that role on
   *     serviceAccountEmail.
   * @param userEmail the email of the user to obtain credentials for
   * @param scopes scopes to request during the authorization grant
   * @param transportFactory HTTP transport factory that creates the transport used to get access
   *     tokens.
   * @param quotaProjectId the project used for quota and billing purposes. Should be null unless
   *     the caller wants to use a project different from the one that owns the impersonated
   *     credential for billing/quota purposes.
   * @return new credentials
   */
  public static DomainWideDelegationCredentials create(
      GoogleCredentials sourceCredentials,
      String serviceAccountEmail,
      List<String> delegates,
      String userEmail,
      List<String> scopes,
      HttpTransportFactory transportFactory,
      String quotaProjectId) {
    return DomainWideDelegationCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setServiceAccountEmail(serviceAccountEmail)
        .setDelegates(delegates)
        .setUserEmail(userEmail)
        .setScopes(scopes)
        .setHttpTransportFactory(transportFactory)
        .setQuotaProjectId(quotaProjectId)
        .build();
  }

  /**
   * @param sourceCredentials the source credential used to acquire the impersonated credentials. It
   *     should be either a user account credential or a service account credential.
   * @param serviceAccountEmail the service account to impersonate
   * @param delegates the chained list of delegates required to grant the final access_token. If
   *     set, the sequence of identities must have "Service Account Token Creator" capability
   *     granted to the preceding identity. For example, if set to [serviceAccountB,
   *     serviceAccountC], the sourceCredential must have the Token Creator role on serviceAccountB.
   *     serviceAccountB must have the Token Creator on serviceAccountC. Finally, C must have Token
   *     Creator on target_principal. If left unset, sourceCredential must have that role on
   *     serviceAccountEmail.
   * @param userEmail the email of the user to obtain credentials for
   * @param scopes scopes to request during the authorization grant
   * @return new credentials
   */
  public static DomainWideDelegationCredentials create(
      GoogleCredentials sourceCredentials,
      String serviceAccountEmail,
      List<String> delegates,
      String userEmail,
      List<String> scopes) {
    return DomainWideDelegationCredentials.newBuilder()
        .setSourceCredentials(sourceCredentials)
        .setServiceAccountEmail(serviceAccountEmail)
        .setDelegates(delegates)
        .setUserEmail(userEmail)
        .setScopes(scopes)
        .build();
  }

  @Override
  public String getQuotaProjectId() {
    return this.quotaProjectId;
  }

  public void setTransportFactory(HttpTransportFactory httpTransportFactory) {
    this.transportFactory = httpTransportFactory;
  }

  @Override
  public boolean createScopedRequired() {
    return this.scopes == null || this.scopes.isEmpty();
  }

  @Override
  public GoogleCredentials createScoped(Collection<String> scopes) {
    return toBuilder()
        .setScopes(new ArrayList<>(scopes))
        .build();
  }
  
  /**
   * Creates a new credentials for a different user
   *
   * @param userEmail the email of the user to obtain credentials for
   * @return new credentials
   */
  @Override
  public GoogleCredentials createDelegated(String userEmail) {
    return toBuilder()
            .setUserEmail(userEmail)
            .build();
  }

  @Override
  protected Map<String, List<String>> getAdditionalHeaders() {
    Map<String, List<String>> headers = super.getAdditionalHeaders();
    if (quotaProjectId != null) {
      return addQuotaProjectIdToRequestMetadata(quotaProjectId, headers);
    }
    return headers;
  }

  private DomainWideDelegationCredentials(Builder builder) {
    this.sourceCredentials = builder.sourceCredentials;
    this.serviceAccountEmail = builder.serviceAccountEmail;
    this.delegates = builder.delegates == null ? new ArrayList<>() : builder.delegates;
    this.userEmail = builder.userEmail;
    this.scopes = builder.scopes;
    this.transportFactory =
        firstNonNull(
            builder.getHttpTransportFactory(),
            getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.quotaProjectId = builder.quotaProjectId;
    this.defaultRetriesEnabled = builder.defaultRetriesEnabled;
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
    if (this.scopes == null || this.scopes.isEmpty()) {
      throw new IllegalStateException("Scopes cannot be null nor empty");
    }
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (this.sourceCredentials.getAccessToken() == null) {
      this.sourceCredentials =
          this.sourceCredentials.createScoped(Collections.singletonList(CLOUD_PLATFORM_SCOPE));
    }

    try {
      this.sourceCredentials.refreshIfExpired();
    } catch (IOException e) {
      throw new IOException("Unable to refresh sourceCredentials", e);
    }
  
    JsonWebToken.Payload assertion = createAssertion(clock.currentTimeMillis());
    String signedJwt = signAssertion(assertion);
    return getUserAccessToken(signedJwt);
  }
  
  JsonWebToken.Payload createAssertion(long currentTime) {
    JsonWebToken.Payload payload = new JsonWebToken.Payload();
    payload.setIssuer(serviceAccountEmail);
    payload.setIssuedAtTimeSeconds(currentTime / 1000);
    //lifetime of user access tokens can't be modified
    payload.setExpirationTimeSeconds(currentTime / 1000 + DEFAULT_LIFETIME_IN_SECONDS);
    payload.setSubject(userEmail);
    payload.put("scope", Joiner.on(' ').join(scopes));
    
    return payload.setAudience(OAuth2Utils.TOKEN_SERVER_URI.toString());
  }
  
  private String signAssertion(JsonWebToken.Payload assertion) throws IOException {
    HttpTransport httpTransport = this.transportFactory.create();
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
  
    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(sourceCredentials);
    HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
  
    String endpointUrl = String.format(IAM_SIGN_JWT_ENDPOINT, this.serviceAccountEmail);
    GenericUrl url = new GenericUrl(endpointUrl);
  
    Map<String, Object> body =
            ImmutableMap.of(
                    "delegates", this.delegates, "payload",
                    OAuth2Utils.JSON_FACTORY.toString(assertion));
  
    HttpContent requestContent = new JsonHttpContent(parser.getJsonFactory(), body);
    HttpRequest request = requestFactory.buildPostRequest(url, requestContent);
    adapter.initialize(request);
    request.setParser(parser);
  
    HttpResponse response;
    try {
      response = request.execute();
    } catch (IOException e) {
      throw new IOException("Error requesting access token", e);
    }
  
    GenericData responseData = response.parseAs(GenericData.class);
    response.disconnect();
  
    return OAuth2Utils.validateString(responseData, "signedJwt", "Expected to find a signedJwt");
  }
  
  /**
   * Exchanges a signed JWT token with an access token for the user
   */
  private AccessToken getUserAccessToken(String signedJwt) throws IOException {
    JsonFactory jsonFactory = OAuth2Utils.JSON_FACTORY;
    
    GenericData tokenRequest = new GenericData();
    tokenRequest.set("grant_type", GRANT_TYPE);
    tokenRequest.set("assertion", signedJwt);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);
    
    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(OAuth2Utils.TOKEN_SERVER_URI), content);
    
    if (this.defaultRetriesEnabled) {
      request.setNumberOfRetries(DEFAULT_NUMBER_OF_RETRIES);
    } else {
      request.setNumberOfRetries(0);
    }
    request.setParser(new JsonObjectParser(jsonFactory));
    
    ExponentialBackOff backoff =
            new ExponentialBackOff.Builder()
                    .setInitialIntervalMillis(INITIAL_RETRY_INTERVAL_MILLIS)
                    .setRandomizationFactor(RETRY_RANDOMIZATION_FACTOR)
                    .setMultiplier(RETRY_MULTIPLIER)
                    .build();
    
    request.setUnsuccessfulResponseHandler(
            new HttpBackOffUnsuccessfulResponseHandler(backoff)
                    .setBackOffRequired(
                            new HttpBackOffUnsuccessfulResponseHandler.BackOffRequired() {
                              @Override
                              public boolean isRequired(HttpResponse response) {
                                int code = response.getStatusCode();
                                return OAuth2Utils.TOKEN_ENDPOINT_RETRYABLE_STATUS_CODES.contains(code);
                              }
                            }));
    
    HttpResponse response;
    String errorTemplate = "Error getting DwD access token for user %s with service account %s: %s";
    
    try {
      response = request.execute();
    } catch (HttpResponseException re) {
      String message = String.format(errorTemplate, userEmail, serviceAccountEmail, re.getMessage());
      throw GoogleAuthException.createWithTokenEndpointResponseException(re, message);
    } catch (IOException e) {
      throw new IOException(String.format(errorTemplate, userEmail, serviceAccountEmail, e.getMessage()), e);
    }
    
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken =
            OAuth2Utils.validateString(responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds =
            OAuth2Utils.validateInt32(responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000L;
    return new AccessToken(accessToken, new Date(expiresAtMilliseconds));
  }
  
  @Override
  public int hashCode() {
    return Objects.hash(
        sourceCredentials, serviceAccountEmail, delegates, userEmail, scopes, defaultRetriesEnabled, quotaProjectId);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("sourceCredentials", sourceCredentials)
        .add("serviceAccountEmail", serviceAccountEmail)
        .add("delegates", delegates)
        .add("userEmail", userEmail)
        .add("scopes", scopes)
        .add("transportFactoryClassName", transportFactoryClassName)
        .add("defaultRetriesEnabled", defaultRetriesEnabled)
        .add("quotaProjectId", quotaProjectId)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof DomainWideDelegationCredentials)) {
      return false;
    }
    DomainWideDelegationCredentials other = (DomainWideDelegationCredentials) obj;
    return Objects.equals(this.sourceCredentials, other.sourceCredentials)
        && Objects.equals(this.serviceAccountEmail, other.serviceAccountEmail)
        && Objects.equals(this.delegates, other.delegates)
        && Objects.equals(this.userEmail, other.userEmail)
        && Objects.equals(this.scopes, other.scopes)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName)
        && Objects.equals(this.defaultRetriesEnabled, other.defaultRetriesEnabled)
        && Objects.equals(this.quotaProjectId, other.quotaProjectId);
  }
  
  @SuppressWarnings("unused")
  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    // properly deserialize the transient transportFactory
    input.defaultReadObject();
    transportFactory = newInstance(transportFactoryClassName);
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends GoogleCredentials.Builder {

    private GoogleCredentials sourceCredentials;
    private String serviceAccountEmail;
    private List<String> delegates;
    private String userEmail;
    private List<String> scopes;
    private HttpTransportFactory transportFactory;
    private String quotaProjectId;
    private boolean defaultRetriesEnabled;

    protected Builder() {}

    protected Builder(GoogleCredentials sourceCredentials, String serviceAccountEmail, String userEmail) {
      this.sourceCredentials = sourceCredentials;
      this.serviceAccountEmail = serviceAccountEmail;
      this.userEmail = userEmail;
    }
  
    private Builder(DomainWideDelegationCredentials credentials) {
      this.sourceCredentials = credentials.sourceCredentials;
      this.serviceAccountEmail = credentials.serviceAccountEmail;
      this.delegates = credentials.delegates;
      this.userEmail = credentials.userEmail;
      this.scopes = credentials.scopes;
      this.transportFactory = credentials.transportFactory;
      this.quotaProjectId = credentials.quotaProjectId;
      this.defaultRetriesEnabled = credentials.defaultRetriesEnabled;
    }
  
    public Builder setSourceCredentials(GoogleCredentials sourceCredentials) {
      this.sourceCredentials = sourceCredentials;
      return this;
    }

    public GoogleCredentials getSourceCredentials() {
      return this.sourceCredentials;
    }

    public Builder setServiceAccountEmail(String serviceAccountEmail) {
      this.serviceAccountEmail = serviceAccountEmail;
      return this;
    }

    public String getServiceAccountEmail() {
      return this.serviceAccountEmail;
    }

    public Builder setDelegates(List<String> delegates) {
      this.delegates = delegates;
      return this;
    }

    public List<String> getDelegates() {
      return this.delegates;
    }

    public Builder setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }
  
    public Builder setUserEmail(String userEmail) {
      this.userEmail = userEmail;
      return this;
    }
  
    public String getUserEmail() {
      return userEmail;
    }

    public List<String> getScopes() {
      return this.scopes;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public Builder setQuotaProjectId(String quotaProjectId) {
      this.quotaProjectId = quotaProjectId;
      return this;
    }
  
  
    public Builder setDefaultRetriesEnabled(boolean defaultRetriesEnabled) {
      this.defaultRetriesEnabled = defaultRetriesEnabled;
      return this;
    }
  
    public boolean isDefaultRetriesEnabled() {
      return defaultRetriesEnabled;
    }

    public DomainWideDelegationCredentials build() {
      return new DomainWideDelegationCredentials(this);
    }
  }
}
