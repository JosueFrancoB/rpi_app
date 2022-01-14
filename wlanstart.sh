#!/bin/bash -e

# Check if running in privileged mode
if [ ! -w "/sys" ] ; then
    echo "[Error] Not running in privileged mode."
    exit 1
fi

conf_file=/app/config/wifi_config.json
if [ -e "$conf_file" ]; then
    echo "Config file exists"
else
    echo "Config file does not exist"
    exit 1
fi

# Default values
INTERFACE=($(jq -r '.interface' $conf_file))
DRIVER=($(jq -r '.driver' $conf_file))
SUBNET=($(jq -r '.subnet' $conf_file))
AP_ADDR=($(jq -r '.ap_addr' $conf_file))
SSID=($(jq -r '.ssid' $conf_file))
HW_MODE=($(jq -r '.hw_mode' $conf_file))
CHANNEL=($(jq -r '.channel' $conf_file))
WPA=($(jq -r '.wpa' $conf_file))
WPA_PASSPHRASE=($(jq -r '.wpa_passphrase' $conf_file))
wpa_key_mgmt=($(jq -r '.wpa_key_mgmt' $conf_file))
wpa_pairwise=($(jq -r '.wpa_pairwise' $conf_file))
rsn_pairwise=($(jq -r '.rsn_pairwise' $conf_file))
wpa_ptk_rekey=($(jq -r '.wpa_ptk_rekey' $conf_file))
ieee80211n=($(jq -r '.ieee80211n' $conf_file))
HT_CAPAB=($(jq -r '.ht_capab' $conf_file))
wmm_enabled=($(jq -r '.wmm_enabled' $conf_file))
MODE=($(jq -r '.mode' $conf_file))
OUTGOINGS=($(jq -r '.outgoings' $conf_file))

WLANUP=$(cat /sys/class/net/wlan0/operstate)

if [ "$WLANUP" == "up" ]; then
  ip link set ${INTERFACE} down
fi

# Attach interface to container in guest mode
if [ "$MODE" == "guest"  ]; then
    echo "Attaching interface to container"

    CONTAINER_ID=$(cat /proc/self/cgroup | grep -o  -e "/docker/.*" | head -n 1| sed "s/\/docker\/\(.*\)/\\1/")
    CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' ${CONTAINER_ID})
    CONTAINER_IMAGE=$(docker inspect -f '{{.Config.Image}}' ${CONTAINER_ID})

    docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "
        PHY=\$(echo phy\$(iw dev ${INTERFACE} info | grep wiphy | tr ' ' '\n' | tail -n 1))
        iw phy \$PHY set netns ${CONTAINER_PID}
    "

    ip link set ${INTERFACE} name wlan0

    INTERFACE=wlan0
fi

cat > "/etc/hostapd.conf" <<EOF
interface=${INTERFACE}
driver=${DRIVER}
ssid=${SSID}
hw_mode=${HW_MODE}
channel=${CHANNEL}
wpa=${WPA}
wpa_passphrase=${WPA_PASSPHRASE}
wpa_key_mgmt=${wpa_key_mgmt}
# TKIP is no secure anymore
#wpa_pairwise=TKIP CCMP
wpa_pairwise=${wpa_pairwise}
rsn_pairwise=${rsn_pairwise}
wpa_ptk_rekey=${wpa_ptk_rekey}
ieee80211n=${ieee80211n}
ht_capab=${HT_CAPAB}
wmm_enabled=${wmm_enabled}
EOF

# unblock wlan
rfkill unblock wlan
rfkill unblock wifi

if [ "$ifwireless" = "1" ] && [ "$INTERFACE" != "wlan0" ]  && \
    type wpa_supplicant >/dev/null 2>&1 && \
    type wpa_cli >/dev/null 2>&1
then
	case "$reason" in
	PREINIT)	wpa_supplicant_start;;
	RECONFIGURE)	wpa_supplicant_reconfigure;;
	DEPARTED)	wpa_supplicant_stop;;
	esac
fi

echo "Setting interface ${INTERFACE}"

# Setup interface and restart DHCP service 
ip link set ${INTERFACE} up
ip addr flush dev ${INTERFACE}
ip addr add ${AP_ADDR}/24 dev ${INTERFACE}

# NAT settings
echo "NAT settings ip_dynaddr, ip_forward"

for i in ip_dynaddr ip_forward ; do 
  if [ $(cat /proc/sys/net/ipv4/$i) ]; then
    echo $i already 1 
  else
    echo "1" > /proc/sys/net/ipv4/$i
  fi
done

cat /proc/sys/net/ipv4/ip_dynaddr 
cat /proc/sys/net/ipv4/ip_forward

if [ "${OUTGOINGS}" ] ; then
   ints="$(sed 's/,\+/ /g' <<<"${OUTGOINGS}")"
   for int in ${ints}
   do
      echo "Setting iptables for outgoing traffics on ${int}..."
      iptables -t nat -D POSTROUTING -s ${SUBNET}/24 -o ${int} -j MASQUERADE > /dev/null 2>&1 || true
      iptables -t nat -A POSTROUTING -s ${SUBNET}/24 -o ${int} -j MASQUERADE

      iptables -D FORWARD -i ${int} -o ${INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT > /dev/null 2>&1 || true
      iptables -A FORWARD -i ${int} -o ${INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT

      iptables -D FORWARD -i ${INTERFACE} -o ${int} -j ACCEPT > /dev/null 2>&1 || true
      iptables -A FORWARD -i ${INTERFACE} -o ${int} -j ACCEPT
   done
else
   echo "Setting iptables for outgoing traffics on all interfaces..."
   iptables -t nat -D POSTROUTING -s ${SUBNET}/24 -j MASQUERADE > /dev/null 2>&1 || true
   iptables -t nat -A POSTROUTING -s ${SUBNET}/24 -j MASQUERADE

   iptables -D FORWARD -o ${INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT > /dev/null 2>&1 || true
   iptables -A FORWARD -o ${INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT

   iptables -D FORWARD -i ${INTERFACE} -j ACCEPT > /dev/null 2>&1 || true
   iptables -A FORWARD -i ${INTERFACE} -j ACCEPT
fi
echo "Configuring DHCP server .."

cat > "/etc/dhcp/dhcpd.conf" <<EOF
option domain-name-servers 8.8.8.8, 8.8.4.4;
option subnet-mask 255.255.255.0;
option routers ${AP_ADDR};
subnet ${SUBNET} netmask 255.255.255.0 {
  range ${SUBNET::-1}100 ${SUBNET::-1}200;
}
EOF

echo "Starting DHCP server .."
dhcpd ${INTERFACE}

echo "Starting HostAP daemon ..."
/usr/sbin/hostapd /etc/hostapd.conf
