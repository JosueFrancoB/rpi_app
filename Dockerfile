FROM python:3.9-alpine
RUN apk update && apk add --no-cache --virtual .pynacl_deps build-base python3-dev libffi-dev
RUN apk add --no-cache libsodium-dev bash gcc jq hostapd iptables dhcp iproute2 docker iw
RUN SODIUM_INSTALL=system pip3 install -Iv pynacl==1.4.0 && pip install -Iv paramiko==2.8.0 flask==2.0.2 flask-redoc==0.2.1 PyYAML==6.0 requests==2.26.0 Flask-Cors==3.0.10
RUN echo "" > /var/lib/dhcp/dhcpd.leases
WORKDIR /app
COPY ./app/ /app/
COPY ./doc.yml /app/doc.yml
COPY wlanstart.sh /bin/wlanstart.sh
RUN chmod +x /bin/wlanstart.sh
CMD ["python3", "app.py"]