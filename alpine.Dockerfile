FROM httpd:alpine

ENV BUILD_DIR /tmp/mod_auth_ofba

ENV APACHE_DEFAULT_CONF /usr/local/apache2/conf/httpd.conf

# add source
RUN mkdir -p ${BUILD_DIR}
COPY ./ ${BUILD_DIR}/

# Example configuration with basic auth for usage demonstration
# Hint: Neither basic auth credentials, nor login or success HTMLs are included, please change according to your needs
RUN mkdir -p "/var/protected";
COPY example.conf conf/example.conf
RUN printf '%s\n' "Include conf/example.conf" >> ${APACHE_DEFAULT_CONF};

# add dependencies, build and install mod_auth_ofba
RUN apk update && apk add --no-cache \
    apache2 \
    apr-util-dev \
    build-base \
  && \
  cd ${BUILD_DIR} && \
  chmod +x ./configure &&\
  chmod +x ./install-sh &&\
  ./configure && \
  make install && \
  rm -fr ${BUILD_DIR} && \
  apk del apr-util-dev build-base

# https://httpd.apache.org/docs/2.4/stopping.html#gracefulstop
# stop gracefully when docker stops, create issue with interactive mode because it's the signal use by the docker engine on windows.
STOPSIGNAL WINCH

# port to expose, refers to the Listen 80 in the embedded httpd.conf
EXPOSE 80

# launch apache
CMD exec /usr/sbin/httpd -D FOREGROUND -f ${APACHE_DEFAULT_CONF}