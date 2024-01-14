import os
from keycloak import KeycloakOpenID
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = f"https://{keyVaultName}.vault.azure.net"


credential = DefaultAzureCredential()

client = SecretClient(vault_url=KVUri, credential=credential)

# Configure client 
keycloak_openid = KeycloakOpenID(server_url=client.get_secret('keycloack-server-url').value,
                    client_id=client.get_secret('client-id').value,
                    realm_name=client.get_secret('realm-name').value,
                    client_secret_key=client.get_secret('keycloak-client-secret-key').value)

def login(username,passw):
    
    # Get Token
    
    token = keycloak_openid.token(username, passw)
   
   
    return token

def token_valitation(token):

    # Introspect Token
    token_info = keycloak_openid.introspect(token)
    token = token_info['active']

    return token


def token_refresh(token):

    # Refresh token
    token = keycloak_openid.refresh_token(token)

    return token