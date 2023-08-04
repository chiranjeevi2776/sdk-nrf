/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief WiFi station sample
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(sta, CONFIG_LOG_DEFAULT_LEVEL);

#include <nrfx_clock.h>
#include <zephyr/kernel.h>
#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>
#include <zephyr/init.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/drivers/gpio.h>

#include <qspi_if.h>

#include "net_private.h"

#include <zephyr/net/socket.h>
#include "common.h"

#define PORT	 1337
#define MAXLINE 1024
#define MSG_WAITALL ZSOCK_MSG_WAITALL

#define WIFI_SHELL_MODULE "wifi"

#if 0
#define WIFI_SHELL_MGMT_EVENTS (NET_EVENT_WIFI_CONNECT_RESULT |		\
				NET_EVENT_WIFI_DISCONNECT_RESULT | \
				NET_EVENT_WIFI_TWT_SLEEP_STATE)
#endif

#define WIFI_SHELL_MGMT_EVENTS (NET_EVENT_WIFI_CONNECT_RESULT |		\
				NET_EVENT_WIFI_DISCONNECT_RESULT)

#define MAX_SSID_LEN        32
#define DHCP_TIMEOUT        70
#define CONNECTION_TIMEOUT  100
#define STATUS_POLLING_MS   300

/* 1000 msec = 1 sec */
#define LED_SLEEP_TIME_MS   100

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)
/*
 * A build error on this line means your board is unsupported.
 * See the sample documentation for information on how to fix this.
 */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

static struct net_mgmt_event_callback wifi_shell_mgmt_cb;
static struct net_mgmt_event_callback net_shell_mgmt_cb;

static struct {
	const struct shell *sh;
	union {
		struct {
			uint8_t connected	: 1;
			uint8_t connect_result	: 1;
			uint8_t disconnect_requested	: 1;
			uint8_t _unused		: 5;
		};
		uint8_t all;
	};
} context;

unsigned int twt_setup = 0;
int sockfd, ctrl_sock_fd = 0;
struct sockaddr_in server_addr, client_addr;
socklen_t addr_len = sizeof(server_addr);
char buffer[1024] = "hello\n";

#define SERVER_IP "192.168.1.11"  // Replace with the IP address of the server
#define SERVER_DATA_PORT 6788      // Replace with the port number used by the server
#define SERVER_CTRL_PORT	6789		      

volatile int stop_traffic = 1;
struct k_sem start_client_sem, start_server_sem;

#if 1
#define STACK_SIZE 4096
#define THREAD_PRIORITY 5

/* Define thread stacks */
K_THREAD_STACK_DEFINE(thread_stack1, STACK_SIZE);
K_THREAD_STACK_DEFINE(thread_stack2, STACK_SIZE);

/* Define thread structures */
struct k_thread udp_client_thread;
struct k_thread udp_server_thread;
#endif

#define ENABLE_TWT 0
#define BUFFER_SIZE 1024

/* Define thread entry functions */
int udp_server(void);
int udp_client(void);

#if ENABLE_TWT
int setupTWT()
{
	struct net_if *iface = net_if_get_default();
        struct wifi_twt_params params = { 0 };

        params.operation = WIFI_TWT_SETUP;

        params.negotiation_type = 0;
        params.setup_cmd = 0;
	params.dialog_token = 1;
	params.flow_id = 1;
	params.setup.responder = 0;
	params.setup.trigger = 1;
	params.setup.implicit = 1;
	params.setup.announce = 1;
	params.setup.twt_wake_interval = 65000;
	params.setup.twt_interval = 1000000;

        if (net_mgmt(NET_REQUEST_WIFI_TWT, iface, &params, sizeof(params))) {
		LOG_INF("TWT SETUP FAILED\n");

                return -ENOEXEC;
        }

        LOG_INF("TWT operation %s with dg: %d, flow_id: %d requested\n",
                wifi_twt_operation2str[params.operation],
                params.dialog_token, params.flow_id);

	twt_setup = 1;

        return 0;
}
#endif

int udp_client()
{
	LOG_INF("Waiting for client sem\n");
	k_sem_take(&start_client_sem, K_FOREVER);
	LOG_INF("UDP Clinet Started\n");
     
	// Create UDP socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG_INF("socket creation failed");
		return -errno;
	}

	memset(&client_addr, 0, sizeof(client_addr));

	// Configure client address
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = INADDR_ANY;
	client_addr.sin_port = htons(0);  // Bind to any available port

	// Bind the socket to the client address
	if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
		LOG_INF("bind failed");
		return -errno;
	}

	memset(&server_addr, 0, sizeof(server_addr));

	// Configure server address
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_DATA_PORT);
	if (inet_pton(AF_INET, SERVER_IP, &(server_addr.sin_addr)) <= 0) {
		perror("inet_pton failed");
		exit(EXIT_FAILURE);
	}
       
	// Send data to the server
	while(1)
	{
		if(stop_traffic == 0)
		{
			sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, addr_len);
			k_sleep(K_USEC(100));
		} else {
			k_sleep(K_MSEC(5));
		}
	}

	// Close the socket
	close(sockfd);

	return 0;
}

int  udp_server(void) 
{

	int sockid;
	char buffer1[MAXLINE];
	struct sockaddr_in servaddr, cliaddr;
	int len, n;

	LOG_INF("#######Waiting for server sem\n");
	k_sem_take(&start_server_sem, K_FOREVER);
	LOG_INF("#######UDP SERVER STARTED\n");

	// Creating socket file descriptor
	if ( (sockid = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		LOG_ERR("socket creation failed - %d", errno);
		return -errno;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	// Filling server information
	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

	// Bind the socket with the server address
	if ( bind(sockid, (const struct sockaddr *)&servaddr,
				sizeof(servaddr)) < 0 )
	{
		LOG_ERR("bind failed %d", errno);
		return -errno;
	}

	len = sizeof(cliaddr); //len is value/result

	LOG_INF("UDP SERVER STARTED\n");
	while(true) {
		n = recvfrom(sockid, (char *)buffer1, MAXLINE,
				MSG_WAITALL, ( struct sockaddr *) &cliaddr,
				&len);
		buffer1[n] = '\0';
		LOG_INF("Message from client : %s\n", buffer1);
	}

	// Close the socket
	close(sockid);
	return 0;
}

int tcp_client()
{
	LOG_INF("TCP CLINET NOT YET IMPLEMENTED\n");

	return 0;
}

int tcp_server()
{
	LOG_INF("TCP SERVER NOT YET IMPLEMENTED\n");

	return 0;
}

/* send/receive traffic based on test case num */
int send_receive_data_frames(int num)
{
	if(test_case[num].client_role == UPLINK)
	{
		if(test_case[num].traffic_type == UDP)
		{
			LOG_INF("Sending UDP Data......\n");
			k_sem_give(&start_client_sem);
			udp_client();
		} else if (test_case[num].traffic_type == TCP) {
			LOG_INF("Sending TCP Data......\n");
			tcp_client();
		} else {
			LOG_INF("Invalid Traffic: choose either TCP/UDP\n");
		}
	} else if(test_case[num].client_role == DOWNLINK) {
		if(test_case[num].traffic_type == UDP)
		{
			LOG_INF("Receving UDP Data......\n");
			udp_server();
		} else if (test_case[num].traffic_type == TCP) {
			LOG_INF("Receving TCP Data......\n");
			tcp_server();
		} else {
			LOG_INF("Invalid Traffic: choose either TCP/UDP\n");
		}
	}

	return 0;
}

int receive_report(int sock)
{
	memset(buffer, 0, BUFFER_SIZE);

	/* Receive a response from the server */
 	recv(sock, buffer, BUFFER_SIZE, 0);
	LOG_INF("Received Report from the SERVER!!!!\n");

	return 0;
}

int send_control_frame(int sock, int num)
{
	send(sock, &test_case[num], sizeof(struct control), 0);
	printf("Control frame sent to server\n");
}

void start_test(int num)
{
	/* send control frame to the server */
	send_control_frame(ctrl_sock_fd, num);

	/* Function to send/receive data frames based on the test case num */
	send_receive_data_frames(num);

	/* Function to receive the report from the server */
	receive_report(ctrl_sock_fd);
}

/* handling control messages with server like start/stop/report */
int init_tcp() 
{
	struct sockaddr_in serv_addr;

	/* Create socket */
	if ((ctrl_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_INF("Socket creation failed");
		return -errno;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERVER_CTRL_PORT);

	/* Convert IPv4 and IPv6 addresses from text to binary form */
	if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
		LOG_INF("Invalid address/ Address not supported");
		return -errno;
	}

	/* Connect to the server */
	if (connect(ctrl_sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		LOG_INF("Connection failed");
		return -errno;
	}

	LOG_INF("Connected To Server!!! \n");
	k_sleep(K_SECONDS(10));

	return ctrl_sock_fd;
}

void toggle_led(void)
{
	int ret;

	if (!device_is_ready(led.port)) {
		LOG_ERR("LED device is not ready");
		return;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		LOG_ERR("Error %d: failed to configure LED pin", ret);
		return;
	}

	while (1) {
		if (context.connected) {
			gpio_pin_toggle_dt(&led);
			k_msleep(LED_SLEEP_TIME_MS);
		} else {
			gpio_pin_set_dt(&led, 0);
			k_msleep(LED_SLEEP_TIME_MS);
		}
	}
}

K_THREAD_DEFINE(led_thread_id, 1024, toggle_led, NULL, NULL, NULL,
		7, 0, 0);

static int cmd_wifi_status(void)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_iface_status status = { 0 };

	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
				sizeof(struct wifi_iface_status))) {
		LOG_INF("Status request failed");

		return -ENOEXEC;
	}

	LOG_INF("==================");
	LOG_INF("State: %s", wifi_state_txt(status.state));

	if (status.state >= WIFI_STATE_ASSOCIATED) {
		uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];

		LOG_INF("Interface Mode: %s",
		       wifi_mode_txt(status.iface_mode));
		LOG_INF("Link Mode: %s",
		       wifi_link_mode_txt(status.link_mode));
		LOG_INF("SSID: %-32s", status.ssid);
		LOG_INF("BSSID: %s",
		       net_sprint_ll_addr_buf(
				status.bssid, WIFI_MAC_ADDR_LEN,
				mac_string_buf, sizeof(mac_string_buf)));
		LOG_INF("Band: %s", wifi_band_txt(status.band));
		LOG_INF("Channel: %d", status.channel);
		LOG_INF("Security: %s", wifi_security_txt(status.security));
		LOG_INF("MFP: %s", wifi_mfp_txt(status.mfp));
		LOG_INF("RSSI: %d", status.rssi);
	}
	return 0;
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (context.connected) {
		return;
	}

	if (status->status) {
		LOG_ERR("Connection failed (%d)", status->status);
	} else {
		LOG_INF("Connected");
		context.connected = true;
	}

	context.connect_result = true;
}

static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (!context.connected) {
		return;
	}

	if (context.disconnect_requested) {
		LOG_INF("Disconnection request %s (%d)",
			 status->status ? "failed" : "done",
					status->status);
		context.disconnect_requested = false;
	} else {
		LOG_INF("Received Disconnected");
		context.connected = false;
	}

	cmd_wifi_status();
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				     uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT:
		LOG_INF("CHIRANJEEVi\n");
		handle_wifi_connect_result(cb);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		handle_wifi_disconnect_result(cb);
		break;
	case NET_EVENT_WIFI_TWT_SLEEP_STATE:
		{
			int *a;
			a = ( int *)(cb->info);
			/* BLOCK Event Received */
			if(*a == WIFI_TWT_STATE_SLEEP)
			{
	                        //LOG_INF("STOP DATA \n");
				stop_traffic = 1;
			}
			/*UNBLOCK Event Received */
			else if(*a == WIFI_TWT_STATE_AWAKE)
			{
	                        //LOG_INF("SEND DATA \n");
				stop_traffic = 0;
			}
			else
			       LOG_INF("UNKNOWN TWT STATE %d \n", *a);	

		}
		break;
	default:
		break;
	}
}

static void print_dhcp_ip(struct net_mgmt_event_callback *cb)
{
	/* Get DHCP info from struct net_if_dhcpv4 and print */
	const struct net_if_dhcpv4 *dhcpv4 = cb->info;
	const struct in_addr *addr = &dhcpv4->requested_ip;
	char dhcp_info[128];

	net_addr_ntop(AF_INET, addr, dhcp_info, sizeof(dhcp_info));

	LOG_INF("DHCP IP address: %s", dhcp_info);
}
static void net_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_IPV4_DHCP_BOUND:
		print_dhcp_ip(cb);
		break;
	default:
		break;
	}
}

static int __wifi_args_to_params(struct wifi_connect_req_params *params)
{
	params->timeout = SYS_FOREVER_MS;

	/* SSID */
	params->ssid = "LMAC_HE-5.60.1_24G"; //CONFIG_STA_SAMPLE_SSID;
	//strcpy(&params->ssid[0], "TWT_NETGEAR_2G");
	params->ssid_length = strlen(params->ssid);

#if defined(CONFIG_STA_KEY_MGMT_WPA2)
	params->security = 1;
#elif defined(CONFIG_STA_KEY_MGMT_WPA2_256)
	params->security = 2;
#elif defined(CONFIG_STA_KEY_MGMT_WPA3)
	params->security = 3;
#else
	params->security = 0;
#endif

#if !defined(CONFIG_STA_KEY_MGMT_NONE)
	params->psk = CONFIG_STA_SAMPLE_PASSWORD;
	params->psk_length = strlen(params->psk);
#endif
	params->channel = WIFI_CHANNEL_ANY;

	/* MFP (optional) */
	params->mfp = WIFI_MFP_OPTIONAL;

	return 0;
}

static int wifi_connect(void)
{
	struct net_if *iface = net_if_get_default();
	static struct wifi_connect_req_params cnx_params;

	context.connected = false;
	context.connect_result = false;
	__wifi_args_to_params(&cnx_params);

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
		     &cnx_params, sizeof(struct wifi_connect_req_params))) {
		LOG_ERR("Connection request failed");

		return -ENOEXEC;
	}

	LOG_INF("Connection requested");

	return 0;
}

int bytes_from_str(const char *str, uint8_t *bytes, size_t bytes_len)
{
	size_t i;
	char byte_str[3];

	if (strlen(str) != bytes_len * 2) {
		LOG_ERR("Invalid string length: %zu (expected: %d)\n",
			strlen(str), bytes_len * 2);
		return -EINVAL;
	}

	for (i = 0; i < bytes_len; i++) {
		memcpy(byte_str, str + i * 2, 2);
		byte_str[2] = '\0';
		bytes[i] = strtol(byte_str, NULL, 16);
	}

	return 0;
}

int main(void)
{
	int i;
	memset(&context, 0, sizeof(context));

	net_mgmt_init_event_callback(&wifi_shell_mgmt_cb,
				     wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS);

	net_mgmt_add_event_callback(&wifi_shell_mgmt_cb);


	net_mgmt_init_event_callback(&net_shell_mgmt_cb,
				     net_mgmt_event_handler,
				     NET_EVENT_IPV4_DHCP_BOUND);

	net_mgmt_add_event_callback(&net_shell_mgmt_cb);

	LOG_INF("Starting %s with CPU frequency: %d MHz", CONFIG_BOARD, SystemCoreClock/MHZ(1));
	k_sleep(K_SECONDS(1));

#if defined(CONFIG_BOARD_NRF7002DK_NRF7001_NRF5340_CPUAPP) || \
	defined(CONFIG_BOARD_NRF7002DK_NRF5340_CPUAPP)
	if (strlen(CONFIG_NRF700X_QSPI_ENCRYPTION_KEY)) {
		char key[QSPI_KEY_LEN_BYTES];
		int ret;

		ret = bytes_from_str(CONFIG_NRF700X_QSPI_ENCRYPTION_KEY, key, sizeof(key));
		if (ret) {
			LOG_ERR("Failed to parse encryption key: %d\n", ret);
			return 0;
		}

		LOG_DBG("QSPI Encryption key: ");
		for (int i = 0; i < QSPI_KEY_LEN_BYTES; i++) {
			LOG_DBG("%02x", key[i]);
		}
		LOG_DBG("\n");

		ret = qspi_enable_encryption(key);
		if (ret) {
			LOG_ERR("Failed to enable encryption: %d\n", ret);
			return 0;
		}
		LOG_INF("QSPI Encryption enabled");
	} else {
		LOG_INF("QSPI Encryption disabled");
	}
#endif /* CONFIG_BOARD_NRF700XDK_NRF5340 */

	LOG_INF("Static IP address (overridable): %s/%s -> %s",
		CONFIG_NET_CONFIG_MY_IPV4_ADDR,
		CONFIG_NET_CONFIG_MY_IPV4_NETMASK,
		CONFIG_NET_CONFIG_MY_IPV4_GW);

	k_sem_init(&start_client_sem, 0, 1);
	k_sem_init(&start_server_sem, 0, 1);
	k_thread_create(&udp_client_thread, thread_stack1, STACK_SIZE,
                    udp_client, NULL, NULL, NULL,
                    THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_create(&udp_server_thread, thread_stack2, STACK_SIZE,
                    udp_server, NULL, NULL, NULL,
                    THREAD_PRIORITY, 0, K_NO_WAIT);

	k_sleep(K_MSEC(100));

	while (1) {
		wifi_connect();

		for (i = 0; i < CONNECTION_TIMEOUT; i++) {
			k_sleep(K_MSEC(STATUS_POLLING_MS));
			cmd_wifi_status();
			if (context.connect_result) {
				break;
			}
		}

		k_sleep(K_MSEC(5000));
		if (context.connected) {
			int test_case_no, ret_val = 0;
			ret_val = init_tcp();
			if(ret_val < 0)
			{
				LOG_INF("Failed to Connect Server\n");
				exit(0);
			}

			LOG_INF("PS MODE: DTIM \n");
			/* run the test cases uplink/downlink/both */
			for(test_case_no = 0; test_case_no < MAX_TEST_CASES; test_case_no++)
			{
				LOG_INF("TEST_CASE: %d\n", test_case_no);
				start_test(test_case_no);
				LOG_INF("TEST CASE: %d Completed\n");
				k_sleep(K_SECONDS(10));
			}
#if ENABLE_TWT
			setupTWT();
#endif
			k_sleep(K_MSEC(1000));
			LOG_INF("Releasing client and server sem\n");
			k_sem_give(&start_client_sem);
			k_sem_give(&start_server_sem);

			k_sleep(K_FOREVER);
		} else if (!context.connect_result) {
			LOG_ERR("Connection Timed Out");
		}
	}

	return 0;
}
