FROM openresty/openresty:1.25.3.1-3-alpine-apk

RUN apk update && \
    apk add --no-cache python3 python3-dev py3-pip supervisor nodejs npm

WORKDIR /expose.sh

COPY python/ /expose.sh/sshserver

COPY nodejs/ /expose.sh/tools

RUN npm install /expose.sh/tools

RUN pip3 install --no-cache-dir --break-system-packages -r /expose.sh/sshserver/requirements.txt

COPY nginx/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

COPY supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
