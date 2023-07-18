package dasniko.keycloak.tokenmapper;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class UserApplicationsMapper extends AbstractOIDCProtocolMapper
	implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  public static final String PROVIDER_ID = "oidc-user-apps-mapper";
  
  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
  
  protected static final Logger logger = Logger.getLogger(UserApplicationsMapper.class);

  static final String USER_ATTRIBUTE_NAME = "userAttributeName";

  static {
    configProperties.add(new ProviderConfigProperty(USER_ATTRIBUTE_NAME, "User Attribute Name", "User attribute name that contains the list od applications id.",
      ProviderConfigProperty.STRING_TYPE, "apps"));

    OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, UserApplicationsMapper.class); // show add to id\/access tokens and userinfo options
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayCategory() {
    return TOKEN_MAPPER_CATEGORY;
  }

  @Override
  public String getDisplayType() {
    return "User Applications Mapper";
  }

  @Override
  public String getHelpText() {
    return "Map the user assigned applications to the \"aud\" token claim.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
    UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

    if (!OIDCAttributeMapperHelper.includeInAccessToken(mappingModel)) {
      return token;
    }

    return addAppsToTokenIfValid(
      getUserAppsAttribute(userSession, mappingModel),
      token);
  }

  @Override
  public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
    UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

    if (!OIDCAttributeMapperHelper.includeInUserInfo(mappingModel)) {
      return token;
    }

    return addAppsToTokenIfValid(
      getUserAppsAttribute(userSession, mappingModel),
      token);
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
      UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

      if (!OIDCAttributeMapperHelper.includeInIDToken(mappingModel)){
        return token;
      }

      return addAppsToTokenIfValid(
        getUserAppsAttribute(userSession, mappingModel),
        token);
    }

    private String getUserAppsAttribute(UserSessionModel userSession, ProtocolMapperModel mappingModel) {
      return userSession.getUser().getFirstAttribute(mappingModel.getConfig().get(USER_ATTRIBUTE_NAME));
    }

    private IDToken addAppsToTokenIfValid(String apps, IDToken token) {
      if (!apps.isBlank()) {
        List<String> appsList = Arrays.asList(apps.split("\\s+"));
        String[] arr = appsList.toArray(new String[0]);
        token.audience(arr);
      }

      return token;
    }

    private AccessToken addAppsToTokenIfValid(String apps, AccessToken token) {
      if (!apps.isBlank()) {
        List<String> appsList = Arrays.asList(apps.split("\\s+"));
        String[] arr = appsList.toArray(new String[0]);
        token.audience(arr);
      }

      return token;
    }
}
