#!/bin/bash
 
DOMAIN_NAME=<FJ-Oの契約番号>
PROJECT_ID=<webにログオンして確認>
USER_NAME=<FJ-Oのユーザ名>
USER_PW=<FJ-Oのパスワード>
CIP_USER=<ChangeIPのユーザ名>
CIP_PASSWD=<ChangeIPのユーザ名>
REGION_ID=jp-east-3

URL=https://identity.${REGION_ID}.cloud.global.fujitsu.com/v3/auth/tokens
CURRENT_DIR=`cd $(dirname ${0}) && pwd`
PUB_KEY_FILE=${CURRENT_DIR}/.ssh/fjo.pub
SECRET_KEY_FILE=${CURRENT_DIR}/.ssh/fjo

KEYPAIR_NAME=auto_fjo
NETWORK_NAME=auto_network
SUBNET_NAME=auto_subnet
ROUTER_NAME=auto_router
SG_NAME=auto_SG
SERVER_NAME=ubuntu
SNAPSHOT_NAME=auto_snapshot
OS_IMAGE_ID=f96bc64e-41ac-4138-9872-bf2dcdae4246
FLAVORS_NAME=C3-1
VOLUME_SIZE=8

case "$1" in
	oslist|create|start|stop|status|os-start|delete|backup|restore|listurl)
		OS_AUTH_TOKEN=$(curl -X POST -si $URL \
			 -H "Content-Type: application/json" \
			 -H "Accept:application/json" \
			 -d '{"auth":{ "identity":{"methods":["password"],"password": {"user":{"domain":{"name":"'$DOMAIN_NAME'"}, "name": "'$USER_NAME'", "password": "'"$USER_PW"'"}}}, "scope": { "project": {"id": "'$PROJECT_ID'"}}}}' | \
			 awk '/X-Subject-Token/ {print $2}' | tr -d '\r\n')
		IDENTITY=https://identity.${REGION_ID}.cloud.global.fujitsu.com
		URL_LIST=`curl -s $IDENTITY/v3/auth/catalog -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN"`
		URL_COMPUTE=`echo ${URL_LIST} | jq -c '.catalog|.[]|.endpoints|.[]|select(.name == "compute")' | grep -F "/v2.1/" | jq -r '.url'`
		URL_NETWORKING=`echo ${URL_LIST} | jq -r '.catalog|.[]|.endpoints|.[]|select(.name == "networking")|.url'`
		URL_KEY=`echo ${URL_LIST} | jq -r '.catalog|.[]|.endpoints|.[]|select(.name == "keymanagement")|.url'`
		URL_IMAGE=`echo ${URL_LIST} | jq -r '.catalog|.[]|.endpoints|.[]|select(.name == "image")|.url'`
		URL_BLOCKSTORAGE=`echo ${URL_LIST} | jq  -c '.catalog|.[]|.endpoints|.[]|select (.name == "blockstorage")' | grep -F "/v3/" | jq -r '.url'`
		;;
	*)
		echo "oslist|create|start|stop|status|os-start|delete|backup|restore|listurl"
		exit
		;;
esac

case "$1" in
	create)
		;;
	oslist)
		curl -Ss ${URL_IMAGE}/v2/images?limit=10000 -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -c '.images[]|[.name, .id]'
		exit
		;;
	listurl)
		curl -s $IDENTITY/v3/auth/catalog -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq  -c '.catalog|.[]|.endpoints|.[]|[.name, .url]'
		exit
		;;
	*)
		SERVER_ID=`curl -Ss ${URL_COMPUTE}/servers -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".servers[]|select (.name == \"${SERVER_NAME}\")|.id"`
		;;
esac

case "$1" in
	status)
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		;;
	start)
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"unshelve" : null }' | jq .
		SERVER_STATUS=""
		until [ "${SERVER_STATUS}" == "ACTIVE" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".server|.status"`
		done
		GIP_PORT_ID=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/os-interface -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.interfaceAttachments[]|.port_id'`
		GIP=`curl -s "${URL_NETWORKING}/v2.0/floatingips?port_id=${GIP_PORT_ID}&fields=floating_ip_address" -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.floatingips[]|.floating_ip_address'`
		wget -O /dev/null "https://nic.ChangeIP.com/nic/update?u=${CIP_USER}&p=${CIP_PASSWD}&ip=${GIP}&hostname=fjo.fjm.ns1.name"
		echo ${SERVER_NAME} start at ${GIP}
		echo hostname fjo.fjm.ns1.name
		;;
	os-start)
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"os-start" : null }' | jq .
		;;
	stop)
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"os-stop" : null }' | jq .
		SERVER_STATUS=""
		until [ "${SERVER_STATUS}" == "SHUTOFF" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.status'`
		done
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"shelve" : null }' | jq .
		;;
	create)
		if [ ! -d ${CURRENT_DIR}/.ssh/ ] ; then
			mkdir ${CURRENT_DIR}/.ssh/
		fi
		if [ -f ${PUB_KEY_FILE} ] ; then
			rm -f ${PUB_KEY_FILE}
		fi
		if [ -f ${SECRET_KEY_FILE} ] ; then
			rm -f ${SECRET_KEY_FILE}
		fi
		ssh-keygen -t rsa -N "" -f ${SECRET_KEY_FILE}
		cp -f ${SECRET_KEY_FILE} ${PUB_KEY_FILE} ~/.ssh/
		PUB_KEY=`cat ${PUB_KEY_FILE}`
		FLAVORS_ID=`curl -Ss ${URL_COMPUTE}/flavors -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".[]|.[]|select(.name == \"${FLAVORS_NAME}\")|.id"`
		curl -Ss ${URL_COMPUTE}/os-keypairs -X POST \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-H "Content-Type: application/json" \
			-d @- <<EOJSON | jq .
{
	"keypair": {
		"name": "${KEYPAIR_NAME}",
		"public_key": "${PUB_KEY}"
	}
}
EOJSON
		curl -Ss ${URL_NETWORKING}/v2.0/networks -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"network": {
		"name": "${NETWORK_NAME}",
		"admin_state_up": true
	}
}
ENDJSON
		NETWORK_ID=`curl -s ${URL_NETWORKING}/v2.0/networks?name=${NETWORK_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		curl -Ss ${URL_NETWORKING}/v2.0/subnets -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"subnet": {
		"network_id": "${NETWORK_ID}",
		"name": "${SUBNET_NAME}",
		"cidr": "172.16.255.0/24",
		"dns_nameservers": [
			"8.8.8.8"
			],
		"allocation_pools": [
			{
				"start": "172.16.255.100",
				"end": "172.16.255.199"
			}
			],
		"gateway_ip": "172.16.255.254",
		"ip_version": 4
	}
}
ENDJSON
		curl -Ss ${URL_NETWORKING}/v2.0/routers -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"router": {
		"name": "${ROUTER_NAME}",
		"admin_state_up": true
	}
}
ENDJSON
		ROUTER_ID=`curl -s ${URL_NETWORKING}/v2.0/routers?name=${ROUTER_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		FIPNET_ID=`curl -s ${URL_NETWORKING}/v2.0/networks?name=fip-net -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		curl -Ss ${URL_NETWORKING}/v2.0/routers/${ROUTER_ID} -X PUT \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"router": {
		"external_gateway_info": {
			"network_id": "${FIPNET_ID}"
		}
	}
}
ENDJSON
		SUBNET_ID=`curl -Ss ${URL_NETWORKING}/v2.0/subnets?name=${SUBNET_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		curl -Ss ${URL_NETWORKING}/v2.0/routers/${ROUTER_ID}/add_router_interface -X PUT \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"subnet_id": "${SUBNET_ID}"
}
ENDJSON
		curl -Ss ${URL_NETWORKING}/v2.0/security-groups -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"security_group": {
		"name": "${SG_NAME}",
		"stateful": true
	}
}
ENDJSON
		SG_ID=`curl -s ${URL_NETWORKING}/v2.0/security-groups?name=${SG_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		curl -Ss ${URL_NETWORKING}/v2.0/security-group-rules -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"security_group_rule": {
		"security_group_id": "${SG_ID}",
		"direction": "ingress",
		"ethertype": "IPv4",
		"protocol": "tcp",
		"port_range_min": "22",
		"port_range_max": "22",
		"remote_ip_prefix": "0.0.0.0/0"
	}
}
ENDJSON
		curl -Ss ${URL_NETWORKING}/v2.0/security-group-rules -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"security_group_rule": {
		"security_group_id": "${SG_ID}",
		"direction": "ingress",
		"ethertype": "IPv4",
		"protocol": "tcp",
		"port_range_min": "1022",
		"port_range_max": "1022",
		"remote_ip_prefix": "0.0.0.0/0"
	}
}
ENDJSON
		curl -Ss ${URL_NETWORKING}/v2.0/security-group-rules -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"security_group_rule": {
		"security_group_id": "${SG_ID}",
		"direction": "ingress",
		"ethertype": "IPv4",
		"protocol": "tcp",
		"port_range_min": "3389",
		"port_range_max": "3389",
		"remote_ip_prefix": "0.0.0.0/0"
	}
}
ENDJSON
		curl -Ss ${URL_NETWORKING}/v2.0/security-group-rules -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
	"security_group_rule": {
		"security_group_id": "${SG_ID}",
		"direction": "ingress",
		"ethertype": "IPv4",
		"protocol": "icmp",
		"remote_ip_prefix": "0.0.0.0/0"
	}
}
ENDJSON
		curl -Ss ${URL_COMPUTE}/servers -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
  "server": {
    "name": "${SERVER_NAME}",
    "flavorRef": "${FLAVORS_ID}",
    "networks": [
      {
        "uuid": "${NETWORK_ID}"
      }
    ],
	"security_groups": [
		{
			"name": "${SG_NAME}"
		}
	],
    "block_device_mapping_v2": [
      {
	    "source_type": "image",
		"destination_type": "volume",
		"delete_on_termination": "true",
		"boot_index": "0",
		"uuid": "${OS_IMAGE_ID}",
        "volume_size": "${VOLUME_SIZE}"
      }
    ],
    "key_name": "${KEYPAIR_NAME}",
	"adminPass": "infinite"
  }
}
ENDJSON
		SERVER_ID=`curl -Ss ${URL_COMPUTE}/servers -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".servers[]|select (.name == \"${SERVER_NAME}\")|.id"`
		SERVER_STATUS=""
		until [ "${SERVER_STATUS}" == "ACTIVE" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".server|.status"`
		done
		GIP_PORT_ID=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/os-interface -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.interfaceAttachments[]|.port_id'`
		curl -Ss ${URL_NETWORKING}/v2.0/floatingips -X POST \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-d @- <<ENDJSON | jq .
{
    "floatingip": {
        "floating_network_id": "${FIPNET_ID}",
        "port_id": "${GIP_PORT_ID}"
    }
}
ENDJSON
		GIP=`curl -s "${URL_NETWORKING}/v2.0/floatingips?port_id=${GIP_PORT_ID}&fields=floating_ip_address" -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.floatingips[]|.floating_ip_address'`
		wget -O /dev/null "https://nic.ChangeIP.com/nic/update?u=${CIP_USER}&p=${CIP_PASSWD}&ip=${GIP}&hostname=fjo.fjm.ns1.name"
		until ( ping -c 1 ${GIP} > /dev/null ) ; do
			sleep 1 
		done
		SSH_OPT="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${SECRET_KEY_FILE}"
		until ( ssh ${SSH_OPT} ubuntu@${GIP} "hostname" > /dev/null 2>&1 ) ; do
			sleep 1
		done
		ssh ${SSH_OPT} ubuntu@${GIP} "sudo rm -f /root/.ssh/authorized_keys ; sudo cp ~ubuntu/.ssh/authorized_keys /root/.ssh/"
		scp ${SSH_OPT} ${CURRENT_DIR}/.ssh/* root@${GIP}:/root/.ssh/
		scp ${SSH_OPT} ${CURRENT_DIR}/setup_ubuntu.sh root@${GIP}:/root/
		ssh ${SSH_OPT} root@${GIP} "chmod 0600 /root/.ssh/*"
		ssh ${SSH_OPT} root@${GIP} "do-release-upgrade -f DistUpgradeViewNonInteractive"
		ssh ${SSH_OPT} root@${GIP} "( sleep 3 && reboot ) &"
		while ( ping -c 1 ${GIP} > /dev/null ) ; do
			sleep 1 
		done
		until ( ping -c 1 ${GIP} > /dev/null ) ; do
			sleep 1 
		done
		until ( ssh ${SSH_OPT} ubuntu@${GIP} "hostname" > /dev/null 2>&1 ) ; do
			sleep 1
		done
		echo ${SERVER_NAME} build at ${GIP}
		echo hostname fjo.fjm.ns1.name
		;;
	delete)
		GIP_ID=`curl -Ss ${URL_NETWORKING}/v2.0/floatingips?fields=id -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.floatingips[]|.id'`
		echo DELETE GIP ${GIP_ID}
		curl -Ss ${URL_NETWORKING}/v2.0/floatingips/${GIP_ID} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		ROUTER_ID=`curl -Ss ${URL_NETWORKING}/v2.0/routers?name=${ROUTER_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		SUBNET_ID=`curl -Ss ${URL_NETWORKING}/v2.0/subnets?name=${SUBNET_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		echo DELETE PORT ${SUBNET_ID}
		curl -Ss ${URL_NETWORKING}/v2.0/routers/${ROUTER_ID}/remove_router_interface -X PUT -H "X-Auth-Token: $OS_AUTH_TOKEN" -d "{\"subnet_id\" : \"${SUBNET_ID}\" }" | jq .
		echo DELETE ROUTER ${ROUTER_ID}
		sleep 10
		curl -Ss ${URL_NETWORKING}/v2.0/routers/${ROUTER_ID} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		SERVER_ID=`curl -Ss ${URL_COMPUTE}/servers -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".servers[]|select (.name == \"${SERVER_NAME}\")|.id"`
		echo DELETE SERVER ${SERVER_ID}
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		NETWORK_ID=`curl -s ${URL_NETWORKING}/v2.0/networks?name=${NETWORK_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		echo DELETE NETWORK ${NETWORK_ID}
		curl -Ss ${URL_NETWORKING}/v2.0/networks/${NETWORK_ID} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		SG_ID=`curl -s ${URL_NETWORKING}/v2.0/security-groups?name=${SG_NAME} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.[]|.id'`
		echo DELETE SG ${SG_ID}
		curl -Ss ${URL_NETWORKING}/v2.0/security-groups/${SG_ID} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		echo DELETE KEYPAIR ${KEYPAIR_NAME}
		curl -Ss ${URL_COMPUTE}/os-keypairs/${KEYPAIR_NAME} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		SNAPSHOT_ID=`curl -Ss ${URL_BLOCKSTORAGE}/snapshots -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".snapshots[] | select ( .volume_id == \"${VOLUME_ID}\" )|.id"`
		curl -Ss ${URL_BLOCKSTORAGE}/snapshots/${SNAPSHOT_ID} -X DELETE -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq .
		;;
	backup)
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"os-stop" : null }' | jq .
		SERVER_STATUS=""
		until [ "${SERVER_STATUS}" == "SHUTOFF" -o "${SERVER_STATUS}" == "SHELVED_OFFLOADED" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.status'`
		done
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"shelve" : null }' | jq .
		until [ "${SERVER_STATUS}" == "SHELVED_OFFLOADED" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.status'`
		done
		VOLUME_ID=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.server|."os-extended-volumes:volumes_attached"[]|.id'`
		curl -Ss ${URL_BLOCKSTORAGE}/snapshots -X POST \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-H "Content-Type: application/json" \
			-d @- <<EOJSON | jq .
{
    "snapshot": {
        "name": "${SNAPSHOT_NAME}",
        "volume_id": "${VOLUME_ID}",
        "force": true,
        "metadata": null
    }
}
EOJSON
		;;
	restore)
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"os-stop" : null }' | jq .
		SERVER_STATUS=""
		until [ "${SERVER_STATUS}" == "SHUTOFF" -o "${SERVER_STATUS}" == "SHELVED_OFFLOADED" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.status'`
		done
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"shelve" : null }' | jq .
		until [ "${SERVER_STATUS}" == "SHELVED_OFFLOADED" ] ; do
			sleep 1
			SERVER_STATUS=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.[]|.status'`
		done
		VOLUME_ID=`curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID} -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r '.server|."os-extended-volumes:volumes_attached"[]|.id'`
		curl -Ss ${URL_BLOCKSTORAGE}/volumes/${VOLUME_ID}/action -X POST \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-H "Content-Type: application/json" \
			-d @- <<EOJSON | jq .
{
    "os-reset_status": {
        "status": "available"
    }
}
EOJSON
		until [ "${VOLUME_STATUS}" == "available" ] ; do
			sleep 1
			VOLUME_STATUS=`curl -Ss ${URL_BLOCKSTORAGE}/volumes/detail -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".volumes[]|select (.id == \"${VOLUME_ID}\")|.status"`
		done
		SNAPSHOT_ID=`curl -Ss ${URL_BLOCKSTORAGE}/snapshots -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".snapshots[] | select ( .volume_id == \"${VOLUME_ID}\" )|.id"`
		curl -Ss ${URL_BLOCKSTORAGE}/volumes/${VOLUME_ID}/action -X POST \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-H "Content-Type: application/json" \
			-H "Accept: application/json" \
			-H "OpenStack-API-Version: volume 3.40" \
			-d @- <<EOJSON | jq .
{
    "revert": {
        "snapshot_id": "${SNAPSHOT_ID}"
    }
}
EOJSON
		VOLUME_STATUS=""
		until [ "${VOLUME_STATUS}" == "available" ] ; do
			sleep 1
			VOLUME_STATUS=`curl -Ss ${URL_BLOCKSTORAGE}/volumes/detail -X GET -H "X-Auth-Token: $OS_AUTH_TOKEN" | jq -r ".volumes[]|select (.id == \"${VOLUME_ID}\")|.status"`
		done
		curl -Ss ${URL_BLOCKSTORAGE}/volumes/${VOLUME_ID}/action -X POST \
			-H "X-Auth-Token: $OS_AUTH_TOKEN" \
			-H "Content-Type: application/json" \
			-d @- <<EOJSON | jq .
{
    "os-reset_status": {
        "status": "in-use"
    }
}
EOJSON
		curl -Ss ${URL_COMPUTE}/servers/${SERVER_ID}/action -X POST -H "X-Auth-Token: $OS_AUTH_TOKEN" -H "Content-Type: application/json" -d '{"unshelve" : null }' | jq .
		;;
	*)
		;;
esac

