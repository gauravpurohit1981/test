#!/usr/bin/env python3
from _pytest.mark import param
import pytest, os
from httpx import AsyncClient
from keycloak import KeycloakOpenID
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

from main import app


keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = f"https://{keyVaultName}.vault.azure.net"


credential = DefaultAzureCredential()

client = SecretClient(vault_url=KVUri, credential=credential)

# Configure client 
keycloak_openid = KeycloakOpenID(server_url=client.get_secret('keycloack-server-url').value,
                    client_id=client.get_secret('client-id').value,
                    realm_name=client.get_secret('realm-name').value,
                    client_secret_key=client.get_secret('keycloak-client-secret-key').value)

token = keycloak_openid.token(client.get_secret('pytest-user').value, client.get_secret('pytest-user-pass').value)

prm = {
    "project":"csc"
}

header = {
    "x-auth-token": token['access_token']
}

header_ref = {
    "x-refresh-token": token['refresh_token']
}


#Login Form
@pytest.mark.asyncio
async def test_login():
    payload = {
  "username": client.get_secret('pytest-user').value,
  "password": client.get_secret('pytest-user-pass').value
}
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/login",params=prm,json=payload,headers=header)
    assert response.status_code == 200

#Token check
@pytest.mark.asyncio
async def test_token_check():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        print(prm)
        response = await ac.post("/token_check",params=prm,headers=header)
        assert response.status_code == 200

#Token_refesh
@pytest.mark.asyncio
async def test_token_refresh():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/token_refresh",params=prm,headers=header_ref)
        assert response.status_code == 200
  
#List access
@pytest.mark.asyncio
async def test_list_access():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/list_access",params=prm,headers=header)
        assert response.status_code == 200
