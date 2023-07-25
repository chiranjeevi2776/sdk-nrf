/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief WiFi shell sample main function
 */
#include <stdio.h>

#include <zephyr/sys/printk.h>
#include <nrfx_clock.h>
#include <zephyr/device.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/rand32.h>
#include <zephyr/kernel.h>
#if defined(CONFIG_USERSPACE11)
#include <zephyr/app_memory/app_memdomain.h>
K_APPMEM_PARTITION_DEFINE(app_partition);
struct k_mem_domain app_domain;
#define APP_BMEM K_APP_BMEM(app_partition)
#define APP_DMEM K_APP_DMEM(app_partition)
static K_HEAP_DEFINE(app_mem_pool, 1024 * 2);
#else
#define APP_BMEM
#define APP_DMEM
#endif

#define TC_PASS 0
#define TC_FAIL 1
#define TC_SKIP 2

#ifndef TC_PASS_STR
#define TC_PASS_STR "PASS"
#endif
#ifndef TC_FAIL_STR
#define TC_FAIL_STR "FAIL"
#endif
#ifndef TC_SKIP_STR
#define TC_SKIP_STR "SKIP"
#endif

static int __wifi_args_to_params(struct wifi_connect_req_params *params)
{
	/* SSID */
	params->ssid = "HE-5.60.1_24G";
	params->ssid_length = strlen(params->ssid);
	params->channel = WIFI_CHANNEL_ANY;
	params->psk = "12345678";
	params->psk_length = strlen(params->psk);
	params->security = WIFI_SECURITY_TYPE_PSK;
	params->mfp = WIFI_MFP_OPTIONAL;

	return 0;
}

static int cmd_wifi_twt_setup_quick()
{
	struct net_if *iface = net_if_get_default();
	struct wifi_twt_params params = { 0 };

	/* Sensible defaults */
	params.operation = WIFI_TWT_SETUP;
	params.negotiation_type = WIFI_TWT_INDIVIDUAL;
	params.setup_cmd = WIFI_TWT_SETUP_CMD_REQUEST;
	params.dialog_token = 1;
	params.flow_id = 1;
	params.setup.responder = 0;
	params.setup.implicit = 1;
	params.setup.trigger = 0;
	params.setup.announce = 0;
	params.setup.twt_wake_interval = 64 * 1024; /* 64ms */
	params.setup.twt_interval = 10 * 60 * 1024 * 1024; /* 60s */

	if (net_mgmt(NET_REQUEST_WIFI_TWT, iface, &params, sizeof(params))) {
		printf("%s with %s failed\n",
			wifi_twt_operation2str[params.operation],
			wifi_twt_negotiation_type2str[params.negotiation_type]);
		return -ENOEXEC;
	}

	printf("TWT operation %s with dg: %d, flow_id: %d requested\n",
		wifi_twt_operation2str[params.operation],
		params.dialog_token, params.flow_id);

	return 0;
}

static int cmd_wifi_twt_teardown(int dialog, int flow_id)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_twt_params params = { 0 };
	long neg_type = 0;
	long setup_cmd = 0;

	int idx = 1;

	params.operation = WIFI_TWT_TEARDOWN;
	neg_type = params.negotiation_type;
	setup_cmd = params.setup_cmd;
	params.dialog_token = dialog;
	params.flow_id = flow_id;

	if (net_mgmt(NET_REQUEST_WIFI_TWT, iface, &params, sizeof(params))) {
		printf("%s with %s failed\n",
			wifi_twt_operation2str[params.operation],
			wifi_twt_negotiation_type2str[params.negotiation_type]);
		return -ENOEXEC;
	}

	printf("TWT operation %s with dg: %d, flow_id: %d requested\n",
		wifi_twt_operation2str[params.operation],
		params.dialog_token, params.flow_id);

	return 0;
}


static int cmd_wifi_twt_teardown_all()
{
	struct net_if *iface = net_if_get_default();
	struct wifi_twt_params params = { 0 };

	params.operation = WIFI_TWT_TEARDOWN;
	params.teardown.teardown_all = 1;

	if (net_mgmt(NET_REQUEST_WIFI_TWT, iface, &params, sizeof(params))) {
		printf("%s with %s failed\n",
			wifi_twt_operation2str[params.operation],
			wifi_twt_negotiation_type2str[params.negotiation_type]);
		return -ENOEXEC;
	}

	printf("TWT operation %s all flows\n", wifi_twt_operation2str[params.operation]);

	return 0;
}


#define WIFI_SHELL_MGMT_EVENTS (NET_EVENT_WIFI_SCAN_RESULT |		\
				NET_EVENT_WIFI_SCAN_DONE |		\
				NET_EVENT_WIFI_CONNECT_RESULT |		\
				NET_EVENT_WIFI_DISCONNECT_RESULT |  \
				NET_EVENT_WIFI_TWT)

static struct net_mgmt_event_callback wifi_shell_mgmt_cb;

static void handle_wifi_twt_event(struct net_mgmt_event_callback *cb)
{
	const struct wifi_twt_params *resp =
		(const struct wifi_twt_params *)cb->info;

	printf("TWT response: %s for dialog: %d and flow: %d\n",
	      wifi_twt_setup_cmd2str[resp->setup_cmd], resp->dialog_token, resp->flow_id);

	/* If accepted, then no need to print TWT params */
	if (resp->setup_cmd != WIFI_TWT_SETUP_CMD_ACCEPT) {
		printf("TWT parameters: trigger: %s wake_interval: %d, interval: %d\n",
		      resp->setup.trigger ? "trigger" : "no_trigger",
		      resp->setup.twt_wake_interval,
		      resp->setup.twt_interval);
	}
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
#if 0		
	case NET_EVENT_WIFI_SCAN_RESULT:
		handle_wifi_scan_result(cb);
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		handle_wifi_scan_done(cb);
		break;

	case NET_EVENT_WIFI_CONNECT_RESULT:
		handle_wifi_connect_result(cb);
		break;
#endif		
	case NET_EVENT_WIFI_TWT:
		handle_wifi_twt_event(cb);
		break;
	default:
		break;
	}
}

static int cmd_wifi_connect()
{
	struct net_if *iface = net_if_get_default();
	struct wifi_connect_req_params cnx_params = { 0 };
	struct wifi_iface_status status = { 0 };

		k_msleep(3000);

	net_mgmt_init_event_callback(&wifi_shell_mgmt_cb,
				     wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS);

	net_mgmt_add_event_callback(&wifi_shell_mgmt_cb);



	__wifi_args_to_params(&cnx_params);

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
		     &cnx_params, sizeof(struct wifi_connect_req_params))) {
		printf("Connection request failed\n");

		return -ENOEXEC;
	}
	k_msleep(3000);

	printf("wifi_connect_req_params: ssid: %s channel: %d, psk: %s, security: %d, mfp: %d\ n",
		      cnx_params.ssid,
		      cnx_params.channel,
		      cnx_params.psk,
			  cnx_params.security,
			  cnx_params.mfp);
	printf("Connection requested\n");
	k_msleep(5000);
	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
			sizeof(struct wifi_iface_status))) {
		printf("Status request failed\n");

		return -ENOEXEC;
	}

	printf("Status: successful\n");
	printf("==================\n");
	printf("State: %s\n", wifi_state_txt(status.state));

	return 0;
}

static int get_wifi_connect()
{
	struct wifi_iface_status status = { 0 };
	struct net_if *iface = net_if_get_default();

	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status, sizeof(struct wifi_iface_status))) {
		printf("Status request failed\n");
		return -ENOEXEC;
	}
	if (status.state == WIFI_STATE_COMPLETED)
		return 0;

	return -1;

}



#if 1 //mqtt
#ifdef CONFIG_NET_CONFIG_SETTINGS
#ifdef CONFIG_NET_IPV61
#define ZEPHYR_ADDR		CONFIG_NET_CONFIG_MY_IPV6_ADDR
#define SERVER_ADDR		CONFIG_NET_CONFIG_PEER_IPV6_ADDR
#else
#define ZEPHYR_ADDR		CONFIG_NET_CONFIG_MY_IPV4_ADDR
#define SERVER_ADDR		CONFIG_NET_CONFIG_PEER_IPV4_ADDR
#endif
#else
#ifdef CONFIG_NET_IPV61
#define ZEPHYR_ADDR     "2001:db8::1"
#define SERVER_ADDR     "2001:db8::2"
#else
#define ZEPHYR_ADDR     "192.168.1.101"
#define SERVER_ADDR     "192.168.1.140"
#endif
#endif

#define SERVER_PORT     1883

#define APP_SLEEP_MSECS     500

#define APP_CONNECT_TRIES     10

#define APP_MAX_ITERATIONS     100

#define MQTT_CLIENTID     "zephyr_publisher11"
#define MQTT_USERNAME     "admin"
#define MQTT_PASSWORD     "password"
/* Set the following to 1 to enable the Bluemix topic format */
#define APP_BLUEMIX_TOPIC     0

/* This is mqtt payload message. */
char payload[] = "DOORS:OPEN_QoSx count";

#define BUFFER_SIZE 256

static APP_BMEM uint8_t rx_buffer[BUFFER_SIZE];
static APP_BMEM uint8_t tx_buffer[BUFFER_SIZE];
static struct mqtt_client client_ctx;
static struct sockaddr broker;
static struct zsock_pollfd fds[1];
static int nfds;
static bool connected;

static void broker_init(void)
{
#if defined(CONFIG_NET_IPV61)
	struct sockaddr_in6 *broker6 = net_sin6(&broker);

	broker6->sin6_family = AF_INET6;
	broker6->sin6_port = htons(SERVER_PORT);
	zsock_inet_pton(AF_INET6, SERVER_ADDR, &broker6->sin6_addr);
#else
	struct sockaddr_in *broker4 = net_sin(&broker);

	broker4->sin_family = AF_INET;
	broker4->sin_port = htons(SERVER_PORT);
	zsock_inet_pton(AF_INET, SERVER_ADDR, &broker4->sin_addr);
#endif
}

static void prepare_fds(struct mqtt_client *client)
{
	if (client->transport.type == MQTT_TRANSPORT_NON_SECURE) {
		fds[0].fd = client->transport.tcp.sock;
	}

	fds[0].events = ZSOCK_POLLIN;
	nfds = 1;
}

static void clear_fds(void)
{
	nfds = 0;
}

static void wait(int timeout)
{
	if (nfds > 0) {
		if (zsock_poll(fds, nfds, timeout) < 0) {
			printf("poll error: %d\n", errno);
		}
	}
}

void mqtt_evt_handler(struct mqtt_client *const client,
		      const struct mqtt_evt *evt)
{
	int err;

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			printf("MQTT connect failed %d\n", evt->result);
			break;
		}

		connected = true;
		printf("[%s:%d] MQTT_EVT_CONNACK: Connected!\n",
			 __func__, __LINE__);

		break;

	case MQTT_EVT_DISCONNECT:
		printf("[%s:%d] MQTT_EVT_DISCONNECT: disconnected %d\n",
			 __func__, __LINE__, evt->result);

		connected = false;
		clear_fds();
		int rc = mqtt_disconnect(&client_ctx);
		if (rc != 0) {
			return TC_FAIL;
		}

		wait(APP_SLEEP_MSECS);
		break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0) {
			printf("MQTT PUBACK error %d\n", evt->result);
			break;
		}

		printf("[%s:%d] MQTT_EVT_PUBACK packet id: %u\n",
			 __func__, __LINE__, evt->param.puback.message_id);

		break;

	case MQTT_EVT_PUBREC:
		if (evt->result != 0) {
			printf("MQTT PUBREC error %d\n", evt->result);
			break;
		}

		printf("[%s:%d] MQTT_EVT_PUBREC packet id: %u\n",
			 __func__, __LINE__, evt->param.pubrec.message_id);

		const struct mqtt_pubrel_param rel_param = {
			.message_id = evt->param.pubrec.message_id
		};

		err = mqtt_publish_qos2_release(client, &rel_param);
		if (err != 0) {
			printf("Failed to send MQTT PUBREL: %d\n",
				 err);
		}

		break;

	case MQTT_EVT_PUBCOMP:
		if (evt->result != 0) {
			printf("MQTT PUBCOMP error %d\n", evt->result);
			break;
		}

		printf("[%s:%d] MQTT_EVT_PUBCOMP packet id: %u\n",
			 __func__, __LINE__, evt->param.pubcomp.message_id);

		break;

	default:
		printf("[%s:%d] Invalid MQTT packet\n", __func__, __LINE__);
		break;
	}
}

static char *get_mqtt_payload(enum mqtt_qos qos)
{
	payload[strlen(payload) - 1] = '0' + qos;

	return payload;
}

static char *get_mqtt_topic(void)
{
	return "sensors";
}
struct mqtt_utf8 user_name;
struct mqtt_utf8 password;
static void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	broker_init();

	user_name.utf8 = (uint8_t *)MQTT_USERNAME;
	user_name.size =  strlen(MQTT_USERNAME);
	password.utf8 = (uint8_t *)MQTT_PASSWORD;
	password.size =  strlen(MQTT_PASSWORD);

	/* MQTT client configuration */
	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (uint8_t *)MQTT_CLIENTID;
	client->client_id.size = strlen(MQTT_CLIENTID);
	client->user_name = &user_name;
	client->password = &password;
	client->protocol_version = MQTT_VERSION_3_1_1;
	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
	client->keepalive = 65530;

	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);
}

static int publish(enum mqtt_qos qos)
{
	struct mqtt_publish_param param;

	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = (uint8_t *)get_mqtt_topic();
	param.message.topic.topic.size =
	strlen(param.message.topic.topic.utf8);
	param.message.payload.data = get_mqtt_payload(qos);
	param.message.payload.len =
	strlen(param.message.payload.data);
	param.message_id = z_impl_sys_rand32_get();
	param.dup_flag = 0U;
	param.retain_flag = 0U;

	return mqtt_publish(&client_ctx, &param);
}

/* In this routine we block until the connected variable is 1 */
static int try_to_connect(struct mqtt_client *client)
{
	int rc, i = 0;

	while (i++ < APP_CONNECT_TRIES && !connected) {
		client_init(&client_ctx);
				printf("===caspar: test connect fail %s %d\n", __func__, __LINE__);
		rc = mqtt_connect(&client_ctx);
		if (rc != 0) {
					printf("===caspar: test connect pass %s %d  %d \n", __func__, __LINE__, rc);
			k_sleep(K_MSEC(APP_SLEEP_MSECS));
			continue;
		}
		prepare_fds(&client_ctx);

		wait(APP_SLEEP_MSECS);
		mqtt_input(&client_ctx);
		if (!connected) {
			mqtt_abort(&client_ctx);
		}
	}
	if (connected) {
		return 0;
	}

	return -EINVAL;
}

static int test_connect(void)
{
	int rc;

	rc = try_to_connect(&client_ctx);
	if (rc != 0) {
		return TC_FAIL;
	}

	return TC_PASS;
}

static int test_pingreq(void)
{
	int rc;

	rc = mqtt_ping(&client_ctx);
	if (rc != 0) {
		return TC_FAIL;
	}

	wait(APP_SLEEP_MSECS);
	mqtt_input(&client_ctx);

	return TC_PASS;
}

static int test_publish(enum mqtt_qos qos)
{
	int rc;

	rc = publish(0);
	if (rc != 0) {
		return TC_FAIL;
	}

	wait(APP_SLEEP_MSECS);
	mqtt_input(&client_ctx);

	/* Second input handle for expected Publish Complete response. */
	/*
	if (qos == MQTT_QOS_2_EXACTLY_ONCE) {
		wait(APP_SLEEP_MSECS);
		mqtt_input(&client_ctx);
	}
	*/
	return TC_PASS;
}

static int test_disconnect(void)
{
	int rc;

	rc = mqtt_disconnect(&client_ctx);
	if (rc != 0) {
		return TC_FAIL;
	}

	wait(APP_SLEEP_MSECS);

	return TC_PASS;
}

void test_mqtt_connect(void)
{
	if (test_connect() == TC_PASS) {
		printf("===caspar: test connect pass %s %d\n", __func__, __LINE__);
	} else {
		printf("===caspar: test connect fail %s %d\n", __func__, __LINE__);
	}
}

void test_mqtt_pingreq(void)
{
	if (test_pingreq() == TC_PASS) {
		printf("===caspar: test connect pass %s %d\n", __func__, __LINE__);
	} else {
		printf("===caspar: test connect fail %s %d\n", __func__, __LINE__);
	}
}

void test_mqtt_publish(void)
{
	if (test_publish(MQTT_QOS_0_AT_MOST_ONCE) == TC_PASS) {
		printf("===caspar: test publish pass %s %d\n", __func__, __LINE__);
	} else {
		printf("===caspar: test publish fail %s %d\n", __func__, __LINE__);
	}
	if (test_publish(MQTT_QOS_1_AT_LEAST_ONCE) == TC_PASS) {
		printf("===caspar: test publish pass %s %d\n", __func__, __LINE__);
	} else {
		printf("===caspar: test publish fail %s %d\n", __func__, __LINE__);
	}
	if (test_publish(MQTT_QOS_2_EXACTLY_ONCE) == TC_PASS) {
		printf("===caspar: test publish pass %s %d\n", __func__, __LINE__);
	} else {
		printf("===caspar: test publish fail %s %d\n", __func__, __LINE__);
	}
}

void test_mqtt_disconnect(void)
{
	if (test_disconnect() == TC_PASS) {
		printf("===caspar: test connect pass %s %d\n", __func__, __LINE__);
	} else {
		printf("===caspar: test connect fail %s %d\n", __func__, __LINE__);
	}
}

#endif
static int i = 0;
static struct k_timer my_timer;

#define STACK_SIZE 2048
#define THREAD_PRIORITY K_PRIO_PREEMPT(8)

static int start_app(void)
{
	int r = 0;
	while(1) {
		i++;
		cmd_wifi_twt_teardown(1, 1);
		k_msleep(1000);
		printf("===11caspar count: %d\n", i);
		test_mqtt_connect();

		if (connected) {
			if (test_publish(i) == TC_PASS) {
				printf("===caspar: test publish pass %s %d\n", __func__, __LINE__);
			} else {
				printf("===caspar: test publish fail %s %d\n", __func__, __LINE__);
			}
		}
		cmd_wifi_twt_setup_quick();
		k_msleep(10000);
	}

	return r;
}

K_THREAD_DEFINE(app_thread, STACK_SIZE,
		start_app, NULL, NULL, NULL,
		THREAD_PRIORITY, K_USER, -1);

void my_work_handler(struct k_work *work)
{
    /* do the processing that needs to be done periodically */
	//k_timer_stop(&my_timer);
    i++;
	//cmd_wifi_twt_teardown_all();
	//k_msleep(500);
	printf("===11caspar count: %d\n", i);
#if 1
	k_thread_start(app_thread);
	k_thread_join(app_thread, K_FOREVER);
#else
	test_mqtt_connect();
#if 0
	if (connected) {
		if (test_publish(i) == TC_PASS) {
			printf("===caspar: test publish pass %s %d\n", __func__, __LINE__);
		} else {
			printf("===caspar: test publish fail %s %d\n", __func__, __LINE__);
		}
	}
#endif
#endif
	//cmd_wifi_twt_setup_quick();
	//k_timer_start(&my_timer, K_SECONDS(10), K_SECONDS(0));
}
K_WORK_DEFINE(my_work, my_work_handler);
void my_expiry_function(struct k_timer *timer_id)
{
	k_work_submit(&my_work);
}

void main(void)
{
#ifdef CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT
	/* For now hardcode to 128MHz */
	nrfx_clock_divider_set(NRF_CLOCK_DOMAIN_HFCLK,
			       NRF_CLOCK_HFCLK_DIV_1);
#endif
	printk("Starting %s with CPU frequency: %d MHz\n", CONFIG_BOARD, SystemCoreClock/MHZ(1));

#ifdef CONFIG_NET_CONFIG_SETTINGS
	/* Without this, DHCPv4 starts on first interface and if that is not Wi-Fi or
	 * only supports IPv6, then its an issue. (E.g., OpenThread)
	 *
	 * So, we start DHCPv4 on Wi-Fi interface always, independent of the ordering.
	 */
	/* TODO: Replace device name with DTS settings later */
	const struct device *dev = device_get_binding("wlan0");

	net_config_init_app(dev, "Initializing network");
#endif

#if 1
	cmd_wifi_connect();

#endif

	//test_mqtt_connect();
	//cmd_wifi_twt_setup_quick();
	//k_timer_init(&my_timer, my_expiry_function, NULL);
	//k_timer_start(&my_timer, K_SECONDS(1), K_SECONDS(0));
	//k_thread_start(app_thread);
	//k_thread_join(app_thread, K_FOREVER);
	while(1) {
		i++;
		cmd_wifi_twt_teardown_all();
		k_msleep(1000);
		printf("===11caspar count: %d\n", i);
		test_mqtt_connect();

		if (connected) {
			if (test_publish(i) == TC_PASS) {
				printf("===caspar: test publish pass %s %d\n", __func__, __LINE__);
			} else {
				printf("===caspar: test publish fail %s %d\n", __func__, __LINE__);
			}
		}
		k_msleep(4000);
		cmd_wifi_twt_setup_quick();
		//mqtt_disconnect(&client_ctx);
		//connected = false;
		k_msleep(600 * 1000);
	}
}
