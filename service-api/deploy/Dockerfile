ARG APP_NAME

FROM alpine:3.21

ARG APP_NAME

EXPOSE 8080/tcp
EXPOSE 9090/tcp

# masscan and zmap dlopen() expect "libpcap.so"; Alpine ships only libpcap.so.1.*.
# File caps let user `ultraviolet` run masscan/zmap with raw sockets when the
# container bounding set includes NET_RAW (see docker-compose cap_add).
# ffmpeg: uv-api RTSP snapshot endpoint (POST /v1/hosts/{ip}/rtsp-snapshot).
RUN apk add --no-cache bash tzdata ca-certificates curl masscan zmap libpcap libcap ffmpeg postgresql16-client \
    && ln -sfn libpcap.so.1 /usr/lib/libpcap.so \
    && setcap 'cap_net_raw,cap_net_admin+ep' /usr/bin/masscan \
    && ZMAP_BIN="$(command -v zmap)" \
    && setcap 'cap_net_raw,cap_net_admin+ep' "$ZMAP_BIN"
RUN addgroup -S ultraviolet && adduser -S -G ultraviolet ultraviolet

COPY --chown=ultraviolet:ultraviolet bin/* /ServiceAPI/
COPY --chown=ultraviolet:ultraviolet deploy/scripts/* /ServiceAPI/
COPY --chown=ultraviolet:ultraviolet deploy/migrations /ServiceAPI/migrations

RUN mkdir -p /ServiceAPI/seed \
	&& chown ultraviolet:ultraviolet /ServiceAPI/seed

RUN chmod +x /ServiceAPI/${APP_NAME} /ServiceAPI/init.sh /ServiceAPI/wait-for-it.sh

ENV APP_BIN=/ServiceAPI/${APP_NAME}

USER ultraviolet

ENTRYPOINT ["/ServiceAPI/init.sh"]
