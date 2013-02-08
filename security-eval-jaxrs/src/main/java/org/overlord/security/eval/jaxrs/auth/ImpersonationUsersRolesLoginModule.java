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
package org.overlord.security.eval.jaxrs.auth;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.ErrorCodes;
import org.jboss.security.auth.spi.UsersRolesLoginModule;

/**
 * @author eric.wittmann@redhat.com
 */
public class ImpersonationUsersRolesLoginModule extends UsersRolesLoginModule {

    private String impersonationPrincipal;
    private String onBehalfOf;
    private String username;

    /**
     * Constructor.
     */
    public ImpersonationUsersRolesLoginModule() {
    }

    /**
     * @see org.jboss.security.auth.spi.UsersRolesLoginModule#initialize(javax.security.auth.Subject,
     *      javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        String val = (String) options.get("impersonationPrincipal");
        if (val != null)
            this.impersonationPrincipal = val;
    }

    /**
     * @see org.jboss.security.auth.spi.UsersRolesLoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        if (this.impersonationPrincipal == null) {
            throw new LoginException(ErrorCodes.NULL_VALUE + "The impersonation principal is not configured.");
        }
        return super.login();
    }

    /**
     * Called by login() to acquire the username and password strings for authentication. This method does no
     * validation of either.
     *
     * @return String[], [0] = username, [1] = password
     * @exception LoginException thrown if CallbackHandler is not set or fails.
     */
    @Override
    protected String[] getUsernameAndPassword() throws LoginException {
        String[] info = super.getUsernameAndPassword();
        String u = info[0];
        String p = info[1];
        // Are we impersonating another user?
        if (u != null && u.equals(this.impersonationPrincipal) && p != null && p.contains("||") && !p.endsWith("||")) {
            int idx = p.indexOf("||");
            info[1] = p.substring(0, idx);
            this.onBehalfOf = p.substring(idx+2);
        }
        this.username = u;
        return info;
    }

    /**
     * @see org.jboss.security.auth.spi.AbstractServerLoginModule#createIdentity(java.lang.String)
     */
    @Override
    protected Principal createIdentity(String username) throws Exception {
        if (super.getIdentity() == null && this.onBehalfOf != null)
            return super.createIdentity(this.onBehalfOf);
        else
            return super.createIdentity(username);
    }

    /**
     * @see org.jboss.security.auth.spi.UsernamePasswordLoginModule#getUsername()
     */
    @Override
    protected String getUsername() {
        return username;
    }

    /**
     * @see org.jboss.security.auth.spi.UsersRolesLoginModule#getUsersPassword()
     */
    @Override
    protected String getUsersPassword() {
        // Make sure the "getUsername()" call will return either the impersonator
        // or the normal username (when not impersonating)
        username = this.onBehalfOf != null ? this.impersonationPrincipal : super.getUsername();
        // The call to "getUsersPassword()" will call back into "getUsername()"
        return super.getUsersPassword();
    }

    /**
     * @see org.jboss.security.auth.spi.UsersRolesLoginModule#getRoleSets()
     */
    @Override
    protected Group[] getRoleSets() throws LoginException {
        // Make sure the "getUsername()" call will always return the normal username (when not
        // impersonating) or the on-behalf-of username (when impersonating)
        username = this.onBehalfOf != null ? this.onBehalfOf : super.getUsername();
        // The call to "getUsersPassword()" will call back into "getUsername()"
        return super.getRoleSets();
    }

}
