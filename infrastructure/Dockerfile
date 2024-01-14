# Setup build arguments with default versions
ARG AZURE_CLI_VERSION=2.15.1
ARG KUBECTL_VERSION=v1.18.10
ARG DEBIAN_VERSION=buster-20201012-slim
ARG PYTHON_MAJOR_VERSION=3.7



FROM debian:${DEBIAN_VERSION} as kubctl
RUN apt-get update
RUN apt-get install -y --no-install-recommends curl=7.64.0-4+deb10u2
RUN apt-get install -y --no-install-recommends ca-certificates
RUN apt-get install -y --no-install-recommends unzip
RUN apt-get install -y --no-install-recommends gnupg
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$( \
        curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt \
    )/bin/linux/amd64/kubectl
RUN chmod +x ./kubectl
RUN cp ./kubectl /usr/local/bin/kubectl

# Build final image
FROM debian:${DEBIAN_VERSION}
LABEL maintainer="bgauduch@github"
ARG SONAR_SCANNER_HOME=/opt/sonar-scanner
ARG SONAR_SCANNER_VERSION=3.3.0.1492-linux
RUN apt-get update \
  && apt-get install -y lsb-release \
  && apt-get clean 


RUN apt-get install -y \
    apt-transport-https \
    software-properties-common \
    build-essential \ 
    python3-pip \
    wget

RUN apt-get install -y software-properties-common &&  apt-get update --fix-missing


RUN apt-get install -y --no-install-recommends curl=7.64.0-4+deb10u2
RUN apt-get install -y --no-install-recommends ca-certificates
RUN apt-get install -y --no-install-recommends unzip
RUN apt-get install -y --no-install-recommends gnupg
RUN pip3 install --ignore-installed PyYAML
RUN apt-get install -y pylint
RUN pylint setup.py || exit 0
#RUN apt-get install -y openjdk-11-jdk
RUN pip3 install pytest \
fastapi==0.61.1 \
psycopg2-binary \
python-keycloak \
aiofiles \
azure.identity \
azure-keyvault-secrets \
httpx \
pytest-asyncio \
python-sonarqube-api


RUN curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
RUN add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/debian \
   $(lsb_release -cs) \
   stable"

RUN apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io
RUN docker --version

COPY --from=kubctl /usr/local/bin/kubectl /usr/local/bin/

RUN curl -fL https://metriton.datawire.io/downloads/linux/edgectl -o /usr/local/bin/edgectl && chmod a+x /usr/local/bin/edgectl

RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

ENV JAVA_HOME=/opt/java/openjdk \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp \
    SONAR_SCANNER_HOME=${SONAR_SCANNER_HOME} \
    SONAR_USER_HOME=${SONAR_SCANNER_HOME}/.sonar \
    PATH=/opt/java/openjdk/bin:${SONAR_SCANNER_HOME}/bin:${NODEJS_HOME}/bin:${PATH} \
    NODE_PATH=${NODEJS_HOME}/lib/node_modules \
    SRC_PATH=/usr/src

WORKDIR /opt

RUN echo "/opt/sonar-scanner-cli.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}.zip"
RUN wget -U "scannercli" -q -O /opt/sonar-scanner-cli.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}.zip \
    && wget -U "scannercli" -q -O /opt/sonar-scanner-cli.zip.asc https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}.zip.asc \
    && wget -U "scannercli" -q -O /opt/sonarsource-public.key https://binaries.sonarsource.com/sonarsource-public.key \
    && gpg --import /opt/sonarsource-public.key \
    && gpg --verify /opt/sonar-scanner-cli.zip.asc /opt/sonar-scanner-cli.zip \
    && unzip sonar-scanner-cli.zip \
    && rm sonar-scanner-cli.zip sonar-scanner-cli.zip.asc \
    && mv sonar-scanner-${SONAR_SCANNER_VERSION} ${SONAR_SCANNER_HOME} \
    && mkdir -p "${SRC_PATH}" "${SONAR_USER_HOME}" "${SONAR_USER_HOME}/cache"\
    && chmod -R 777 "${SRC_PATH}"

RUN sonar-scanner -v 
RUN sonar-scanner --help

WORKDIR /workspace
RUN groupadd --gid 1001 nonroot \
  # user needs a home folder to store azure credentials
  && useradd --gid nonroot --create-home --uid 1001 nonroot \
  && chown nonroot:nonroot /workspace
USER nonroot

CMD ["bash"]