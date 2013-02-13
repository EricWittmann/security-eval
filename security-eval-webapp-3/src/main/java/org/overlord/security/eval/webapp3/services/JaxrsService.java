/*
 * Copyright 2013 JBoss Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.overlord.security.eval.webapp3.services;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.impl.client.DefaultHttpClient;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;

/**
 * @author eric.wittmann@redhat.com
 */
public class JaxrsService {

    private static final String ENDPOINT = "http://localhost:8080/security-eval-jaxrs/greeting";

    private HttpServletRequest context;

    /**
     * Constructor.
     */
    public JaxrsService(HttpServletRequest context) {
        this.context = context;
    }

    /**
     * @return
     */
    public String doGreeting() {
        try {
            ClientRequest request = new ClientRequest(ENDPOINT, getBasicAuthExecutor());
            ClientResponse<String> response = request.get(String.class);
            int status = response.getStatus();
            System.out.println("Greeting status: " + status);
            return response.getEntity();
        } catch (Throwable e) {
            return "FAIL: " + e.getMessage();
        }

    }

    /**
     * @return
     */
    private ClientExecutor getBasicAuthExecutor() {
        String currentUser = this.context.getRemoteUser();
        String password = getCurrentUserAuthToken();
        Credentials credentials = new UsernamePasswordCredentials(currentUser, password);
        DefaultHttpClient httpClient = new DefaultHttpClient();
        httpClient.getCredentialsProvider().setCredentials(AuthScope.ANY, credentials);
        ClientExecutor clientExecutor = new ApacheHttpClient4Executor(httpClient);
        return clientExecutor;
    }

    /**
     * @return
     */
    private String getCurrentUserAuthToken() {
        return "TOKEN";
    }

}
