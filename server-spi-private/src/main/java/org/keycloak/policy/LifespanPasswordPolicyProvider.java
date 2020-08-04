/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.policy;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.util.List;
import java.util.stream.Collectors;

public class LifespanPasswordPolicyProvider implements PasswordPolicyProvider {

    private static final String ERROR_MESSAGE = "invalidPasswordLifespanMessage";

    private KeycloakSession session;

    public LifespanPasswordPolicyProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(String username, String password) {
        return null;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        PasswordPolicy policy = session.getContext().getRealm().getPasswordPolicy();
        int lifespanPolicyValue = policy.getPolicyConfig(LifespanPasswordPolicyProviderFactory.ID);

        // Only check for password lifespan if its value is > 0 and the user has not been asked to reset its password
        if (!user.getRequiredActions().contains(UserModel.RequiredAction.UPDATE_PASSWORD.name()) &&
                lifespanPolicyValue > 0) {
            List<CredentialModel> passwordHistory = session.userCredentialManager().getStoredCredentialsByType(realm, user, PasswordCredentialModel.PASSWORD_HISTORY);
            List<CredentialModel> recentPasswordHistory = getLast(passwordHistory);

            if (recentPasswordHistory.size() > 0) {
                if (Time.currentTimeMillis() - recentPasswordHistory.get(0).getCreatedDate() < lifespanPolicyValue * 1000) {
                    return new PolicyError(ERROR_MESSAGE, lifespanPolicyValue);
                }
            }
        }
        return null;
    }

    private List<CredentialModel> getLast(List<CredentialModel> passwordHistory) {
        return passwordHistory.stream()
                .sorted(CredentialModel.comparingByStartDateDesc())
                .limit(1)
                .collect(Collectors.toList());
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, LifespanPasswordPolicyProviderFactory.DEFAULT_VALUE);
    }

    @Override
    public void close() {
    }

}
