#!/usr/bin/env python3
import os
from keycloak import KeycloakOpenID
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = f"https://{keyVaultName}.vault.azure.net"


credential = DefaultAzureCredential()

client = SecretClient(vault_url=KVUri, credential=credential)

def access_check(token):
    # Configure client 
    keycloak_openid = KeycloakOpenID(server_url=client.get_secret('keycloack-server-url').value,
                        client_id=client.get_secret('client-id').value,
                        realm_name=client.get_secret('realm-name').value,
                        client_secret_key=client.get_secret('keycloak-client-secret-key').value)

    # Introspect Token
    token_info = keycloak_openid.introspect(token)
    
    token = False
    try:
        token = token_info['active']
                
    except:
        token = "Good try you don't have permssion for that action level1"

    return token,token_info["username"]