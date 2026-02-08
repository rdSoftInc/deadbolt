FROM amazoncorretto:21-alpine-jdk

RUN apk add --no-cache wget unzip

RUN wget https://github.com/skylot/jadx/releases/download/v1.5.3/jadx-1.5.3.zip \
 && unzip jadx-1.5.3.zip -d /opt/jadx \
 && chmod +x /opt/jadx/bin/jadx \
 && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
 && rm jadx-1.5.3.zip

ENTRYPOINT ["jadx"]