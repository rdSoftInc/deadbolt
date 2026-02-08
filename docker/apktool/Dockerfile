FROM amazoncorretto:21-alpine-jdk

RUN apk add --no-cache wget unzip

RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
 && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.12.1.jar \
 && mv apktool_2.12.1.jar /usr/local/bin/apktool.jar \
 && chmod +x apktool \
 && mv apktool /usr/local/bin/apktool

ENTRYPOINT ["apktool"]