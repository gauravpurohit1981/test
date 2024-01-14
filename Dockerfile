FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8

COPY ./app /app

RUN apt-get update -y
RUN apt-get upgrade -y libexif-dev

RUN pip3 install -r /app/requirements.txt

ENV KEY_VAULT_NAME="KEY_VAULT_NAME" \
    AZURE_TENANT_ID="AZURE_TENANT_ID" \
    AZURE_CLIENT_ID="AZURE_CLIENT_ID" \
    AZURE_CLIENT_SECRET="AZURE_CLIENT_SECRET"

EXPOSE 80