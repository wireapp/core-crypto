FROM quay.io/keycloak/keycloak:22.0.5

WORKDIR /opt/keycloak

# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair \
    -storepass password \
     -storetype PKCS12 \
     -keyalg RSA \
     -keysize 2048 \
     -dname "CN=server" \
     -alias server \
     -ext "SAN:c=DNS:localhost,IP:127.0.0.1" \
     -keystore conf/server.keystore

COPY tests/utils/docker/keycloak/e2ei-keycloak-oidc-mapper-0.0.1-SNAPSHOT.jar /opt/keycloak/providers/e2ei-keycloak-oidc-mapper.jar

ENV KC_FEATURES="client-policies"
ENV KC_DB="dev-file"
ENV KC_HEALTH_ENABLED="true"
ENV KC_LOG_LEVEL="info"

RUN sh /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
