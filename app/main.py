#!/usr/bin/env python3
# -*- coding: cp1252 -*-
import os
import requests
from login import login
from login import token_valitation ,token_refresh
from list_access import list_access_function
from typing import Optional, List
import json
from authorazation import access_check
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel,Field
from enum import Enum
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.staticfiles import StaticFiles
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


keyVaultName = os.environ["KEY_VAULT_NAME"]
KVUri = f"https://{keyVaultName}.vault.azure.net"


credential = DefaultAzureCredential()

client = SecretClient(vault_url=KVUri, credential=credential)

class LoginForm(BaseModel):
    username: str = Field(..., description="Username",) 
    password: str = Field(..., description="Password",)
        


app = FastAPI(
    termsOfService="http://swagger.io/terms/",
    docs_url=None, 
    redoc_url=None,      
)

app.mount("/static", StaticFiles(directory="static"), name="static")
services = ["automation","compliance","compliance-posture","compute","compute-container","compute-defenders","compute-deployments","compute-radar","alerts","host-scan","image-scan","images","investigation","policy","reports","resources"]
def load_all_jsons():    
    headers = {
     
        "content-type": "application/json; charset=UTF-8"
    }
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Try CSC APIs",
        description="Welcome to Security Compliance using Swagger",
        version="0.0.2",
        routes=app.routes,
    )

    keys = []
    for k in  openapi_schema['paths'].keys():
            keys.append(k)
  
    for j in keys:           
        openapi_schema['paths']['/login'+j] =  openapi_schema['paths'].pop(j)

    for x in services:
        keys = []
        response = requests.request("GET",  client.get_secret('server-url').value+x+"/openapi.json",  headers=headers, verify=False)
        index_o = response.json()
 	
        for k in  index_o['paths'].keys():
            keys.append(k)
  
        for j in keys:           
            index_o['paths']['/'+x+j] =  index_o['paths'].pop(j)


        openapi_schema['paths'].update(index_o['paths'])
        openapi_schema['components']['schemas'].update(index_o['components']['schemas'])

    openapi_schema["info"]["x-logo"] = {
        "url": "https://jobs.technology/Portals/59/logo_hz_blk_rgb_300.png?ver=2018-10-17-094900-000"
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = load_all_jsons

credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please re-login your credentials have expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

permission_exception = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied, not authorized to use.",
        )

token_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access denied, your token is invalid",
        )

responses = {
    401: {"description": "Please re-login your credentials have expired OR Access denied, your token is invalid OR system error informations"},
    403: {"description": "Access denied, not authorized to use."}
}

@app.get("/api/hello")
async def hello():
    headers = {     
        "content-type": "application/json; charset=UTF-8"
    }
    res=[]
    for x in services:     
        response = requests.request("GET",  client.get_secret('server-url').value+x+"/openapi.json",  headers=headers, verify=False)
        if response.status_code == 200:
            res.append({
                "Agent": x,
                "report_satus": "API is reachable status code: " + str(response.status_code)
                })
        else:
            res.append({
                "Agent": x,
                "report_satus": "API is unreachable status code: " + str(response.status_code)
                })


    return {"reports": res}

# This is for adding policies
# @app.get("/add_policy")
# async def root():
#     out = add_function("e558e2e1-dcdf-479f-b719-18d811a4b8af","LWDA7rYubl1BKiRphSm/XgVK0fI=")
#     return {"message": str(out)}

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    load_all_jsons()
    return get_swagger_ui_html(
        openapi_url='/login'+app.openapi_url,
        title=app.title + " - Swagger UI",
        
    )
@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    load_all_jsons()
    return get_redoc_html(
        openapi_url='/login'+app.openapi_url,
        title=app.title + " - ReDoc",
       
    ) 

@app.post("/login",responses={**responses},tags=["authorisation"])
async def login_form(login_f: LoginForm):
    """
    **Login**\n
    Returns a JWT auth token for accessing the cnacso APIs.  To generate a token, you must have a username and the password. Cnasco project requires this JWT in the request header to authorize API access. Note that JWT maintain the same level of permissions as the permission group of the account. 
 
    """
    try:
        out = login(login_f.username, login_f.password)
    except Exception as e:
        try:
            spliter = str(e).split(': ')
            msg = json.loads(json.loads(json.dumps(str(spliter[1]).replace('b\'','').replace('\'',''))))
        except Exception as l:
            credentials_exception = HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail= str(e),
                headers={"WWW-Authenticate": "Bearer"},
            )
            raise credentials_exception

        if "401" in str(e):
            credentials_exception = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail= msg['error_description'],
                headers={"WWW-Authenticate": "Bearer"},
            )
            raise credentials_exception
        return json.dumps(msg)
    
    return {"message": out}

@app.post("/token_check",responses={**responses},tags=["authorisation"])
async def token_check(x_auth_token: str = Header(...)):
    """
    **Token Check**\n
    Check of JWT auth token for accessing the cnacso APIs. 

    
    """
    try:
        out = token_valitation(x_auth_token)
    except Exception as e:
        spliter = str(e).split(': ')
        msg = json.loads(json.loads(json.dumps(str(spliter[1]).replace('b\'','').replace('\'',''))))

        if "401" in str(e):
            credentials_exception_in = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail= msg['error_description'],
                headers={"WWW-Authenticate": "Bearer"},
            )
            raise credentials_exception_in
        return json.dumps(msg)
    
    if out == False:
        raise credentials_exception

    return {"message": out}

@app.post("/token_refresh",responses={**responses},tags=["authorisation"])
async def token_refresh_web(x_refresh_token: str = Header(...)):
    """
    **Token Check**\n
    Refresh of JWT auth token for accessing the cnacso APIs. 
    
    """
    try:
        out = token_refresh(x_refresh_token)
    except Exception as e:
        spliter = str(e).split(': ')
        msg = json.loads(json.loads(json.dumps(str(spliter[1]).replace('b\'','').replace('\'',''))))

        if "401" in str(e) or "invalid_grant" in  str(e) :
            credentials_exception_in = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail= msg['error_description'],
                headers={"WWW-Authenticate": "Bearer"},
            )
            raise credentials_exception_in
        return json.dumps(msg)
    
    if out == False:
        raise credentials_exception

    return {"message": out}

@app.get("/list_access",responses={**responses},tags=["authorisation"])
async def list_access(x_auth_token: str = Header(...)):
    """
    **Permissions**\n
    Use of JWT auth token for accessing the cnacso APIs permissions for user view. 
    
    """
    try:
        access_result,username = access_check(x_auth_token)
        if access_result:
            out = list_access_function(user2query=username)
        else:
            raise credentials_exception
       
    except Exception as e:
        if access_result == False:
            raise credentials_exception
        out = str(e)
     
    return {"message": out}
