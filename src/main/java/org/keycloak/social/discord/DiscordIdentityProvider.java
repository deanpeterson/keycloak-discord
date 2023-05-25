/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.social.discord;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.messages.Messages;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;

import javax.ws.rs.core.Response;
import java.util.Set;

/**
 * @author <a href="mailto:wadahiro@gmail.com">Hiroyuki Wada</a>
 */
public class DiscordIdentityProvider extends AbstractOAuth2IdentityProvider<DiscordIdentityProviderConfig>
        implements SocialIdentityProvider<DiscordIdentityProviderConfig> {

    private static final Logger log = Logger.getLogger(DiscordIdentityProvider.class);

    public static final String AUTH_URL = "https://discord.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://discord.com/api/oauth2/token";
    public static final String PROFILE_URL = "https://discord.com/api/users/@me";
    public static final String GROUP_URL = "https://discord.com/api/users/@me/guilds";
    public static final String DEFAULT_SCOPE = "identify email";
    public static final String GUILDS_SCOPE = "guilds";

    private static final String ADD_MEMBER_URL_FORMAT = "https://discord.com/api/guilds/%s/members/%s";

    public DiscordIdentityProvider(KeycloakSession session, DiscordIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"));

        user.setUsername(getJsonProperty(profile, "username") + "#" + getJsonProperty(profile, "discriminator"));
        user.setEmail(getJsonProperty(profile, "email"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        log.info("doGetFederatedIdentity()");
        JsonNode profile = null;
        try {
            profile = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from discord.", e);
        }

        if (getConfig().hasAllowedGuilds()) {
            if (!isAllowedGuild(accessToken)) {
                throw new ErrorPageException(session, Response.Status.FORBIDDEN, Messages.INVALID_REQUESTER);
            }
        }

        BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);
        user.setUserAttribute("discordUser", user.getId());
        
        user.getContextData().put("access_token", accessToken);

        // Iterate over the allowed guilds and add the user to each one
        Set<String> guildsToJoin = getConfig().getGuildsToJoinAsSet();
        log.info("list of guilds to join: " + guildsToJoin.toString());
        for (String guildId : guildsToJoin) {
            log.info("joining user: " + user.getId() + " to guild: " + guildId);
            addMemberToGuild(guildId, user.getId(), accessToken);
        }

        return user;
    }

    private void addMemberToGuild(String guildId, String userId, String accessToken) {
        String addMemberUrl = String.format(ADD_MEMBER_URL_FORMAT, guildId, userId);
    
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpPut putRequest = new HttpPut(addMemberUrl);
            putRequest.addHeader("Authorization", "Bot " + getConfig().getBotToken());
            putRequest.addHeader("Content-Type", "application/json");
    
            String jsonBody = "{\"access_token\": \"" + accessToken + "\"}";
            StringEntity jsonEntity = new StringEntity(jsonBody);
            putRequest.setEntity(jsonEntity);
            CloseableHttpResponse response = httpclient.execute(putRequest);
            // handle response here
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not add member to guild.", e);
        }
    }

    protected boolean isAllowedGuild(String accessToken) {
        try {
            JsonNode guilds = SimpleHttp.doGet(GROUP_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
            Set<String> allowedGuilds = getConfig().getAllowedGuildsAsSet();
            for (JsonNode guild : guilds) {
                String guildId = getJsonProperty(guild, "id");
                if (allowedGuilds.contains(guildId)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain guilds the current user is a member of from discord.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        if (getConfig().hasAllowedGuilds()) {
            return DEFAULT_SCOPE + " " + GUILDS_SCOPE;
        } else {
            return DEFAULT_SCOPE;
        }
    }
}
