#!/bin/bash

logfile=/tmp/cert-renew.log

docker stop nginx

echo "logging to [$logfile]" | tee "$logfile"

echo "MONTHLY CERT RENEWAL" | tee -a "$logfile"

/scripts/fwapply --renew-cert | tee -a "$logfile"

firstname=srv0.example.com

letsencrypt certonly -v -n --agree-tos --email srv0@example.com --expand --standalone \
	-d $firstname \
	-d cloud.example.com \
	-d cloud-sync.example.com \
	-d doc.example.com \
	-d zimbra.example.com \
	-d dc01.example.com \
	-d mail.example.com \
	-d autodiscover.example.com \
	-d sec.example.com \
	| tee -a "$logfile"

/scripts/fwapply | tee -a "$logfile"

echo "FINISHED" | tee -a "$logfile"

if [ "$(ls /etc/letsencrypt/live/ | wc -l)" != "1" ]; then

	echo "multiple folders on live, recurse..." | tee -a "$logfile"
	rm -fr /etc/letsencrypt
	renew-certs

elif [ "$(diff /root/fullchain.pem /etc/letsencrypt/live/$firstname/fullchain.pem)" != "" ]; then

	echo "cert change detected" | tee -a "$logfile"

	# tune permission of privkey to allow dc ldaps works
	find /etc/letsencrypt/ -iname "privkey*" -exec chmod 600 "{}" \;

	# domain controller
	docker restart dc01

	# create root cert
	cp -f /scripts/letsencrypt-root.pem /etc/letsencrypt/live/$firstname/root.pem

	# zimbra
	rm -fr /nas/data/zimbra/letsencrypt
	cp -r /etc/letsencrypt /nas/data/zimbra
	docker exec zimbra /opt/install-letsencrypt

	cp -f /etc/letsencrypt/live/$firstname/fullchain.pem /root/fullchain.pem
fi

# nginx
docker start nginx

# status

statuslog=/status/cert.json

certdst=/etc/letsencrypt/live/$firstname/fullchain.pem

validuntil="$(date --date="$(openssl x509 -enddate -noout -in "$certdst" | cut -d= -f 2)" --iso-8601)"

jdetails=$(echo "$details" | /scripts/json-escape)

cat << EOF > $statuslog
{
"date" : "$(date +%Y.%m.%d-%H.%M.%S)",
"status" : "$status",
"details" : "$jdetails",
"validuntil": "$validuntil"
}
EOF
