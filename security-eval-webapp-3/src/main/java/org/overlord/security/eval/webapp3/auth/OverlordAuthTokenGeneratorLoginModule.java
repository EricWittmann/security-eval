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
package org.overlord.security.eval.webapp3.auth;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext;

/**
 * @author eric.wittmann@redhat.com
 */
public class OverlordAuthTokenGeneratorLoginModule implements LoginModule {

    /**
     * Constructor.
     */
    public OverlordAuthTokenGeneratorLoginModule() {
    }

    /**
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        System.out.println("initialize: " + subject);
    }

    /**
     * @see javax.security.auth.spi.LoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        // Generate an auth token for this user.
        System.out.println("Generate token for: " + ServiceProviderSAMLContext.getUserName());
        return true;
    }

    /**
     * @see javax.security.auth.spi.LoginModule#commit()
     */
    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    /**
     * @see javax.security.auth.spi.LoginModule#abort()
     */
    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    /**
     * @see javax.security.auth.spi.LoginModule#logout()
     */
    @Override
    public boolean logout() throws LoginException {
        // Perhaps try to invalidate the token here?
        return true;
    }

}
