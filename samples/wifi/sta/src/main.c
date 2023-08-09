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
#include <zephyr/types.h>

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
char report_buffer[1024];
struct server_report local_report;

#define SERVER_IP "192.168.1.140"  // Replace with the IP address of the server
#define SERVER_DATA_PORT 6788      // Replace with the port number used by the server
#define SERVER_CTRL_PORT	6789		      
#define ENABLE_KTHREADS 0

volatile int stop_traffic = 1;


#if ENABLE_KTHREADS 
#define STACK_SIZE 4096
#define THREAD_PRIORITY 5

/* Define thread stacks */
K_THREAD_STACK_DEFINE(thread_stack1, STACK_SIZE);
K_THREAD_STACK_DEFINE(thread_stack2, STACK_SIZE);

/* Define thread structures */
struct k_thread udp_client_thread;
struct k_thread udp_server_thread;

struct k_sem start_client_sem, start_server_sem;
#endif

#define ENABLE_TWT 0
#define BUFFER_SIZE 1024

/* Define thread entry functions */
int udp_server(int num);
int udp_client(int num);

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

int udp_client(int num)
{
	unsigned long long start_time_ms = k_uptime_get(); //returns time in ms from the boot
	int total_duration = test_case[num].duration * 1000; //Converting into ms

#if ENABLE_KTHREADS
	LOG_INF("Waiting for client sem\n");
	k_sem_take(&start_client_sem, K_FOREVER);
#endif
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
       
	start_time_ms = k_uptime_get();
	// Send data to the server
	while((k_uptime_get() - start_time_ms) < total_duration)
	{
		sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, addr_len);
		k_sleep(K_USEC(100));
	}

	/* Send Empty Msg to indicate End of TX */
	{
		char empty_data = '\0';
		sendto(sockfd, &empty_data, 0, 0, (struct sockaddr *)&server_addr, addr_len);
	}

	// Close the socket
	close(sockfd);

	return 0;
}

// Function to convert network-order uint64_t to double
uint64_t double_to_uint64(double value) {
    uint64_t result;
    memcpy(&result, &value, sizeof(uint64_t));
    return (result);
}

double uint64_to_double(uint64_t value)
{
	double result;

	memcpy(&result, &value, sizeof(double));
	return result;
}

int udp_server(int num)
{
	char buffer1[MAXLINE];
	int sockid, len, bytes;
	int prev_packet_time_ms = 0, current_packet_time_ms, jitter;
	 int jitter_sum_ms = 0;
	uint32_t current_time, start_time;
	double elapsed_time = 0.0, throughput_mbps = 0;
	struct sockaddr_in servaddr, cliaddr;

#if ENABLE_KTHREADS
	LOG_INF("#######Waiting for server sem\n");
	k_sem_take(&start_server_sem, K_FOREVER);
#endif
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
	servaddr.sin_port = htons(SERVER_DATA_PORT);

	// Bind the socket with the server address
	if ( bind(sockid, (const struct sockaddr *)&servaddr,
				sizeof(servaddr)) < 0 )
	{
		LOG_ERR("bind failed %d", errno);
		return -errno;
	}

	len = sizeof(cliaddr); //len is value/result

	memset(&local_report, 0 , sizeof(struct server_report));

        start_time = k_uptime_get_32();
	while(1) {
		bytes = recvfrom(sockid, (char *)buffer1, MAXLINE,
				MSG_WAITALL, ( struct sockaddr *) &cliaddr,
				&len);
		if(bytes <= 0)
		{
			LOG_INF("END OF UDP RX\n");
			break;
		}
		//LOG_INF("Bytes %d\n", bytes);

		local_report.bytes_received += bytes;
		local_report.packets_received++;

		// Calculate throughput
		current_time = k_uptime_get_32();
		elapsed_time = (double)(current_time - start_time) / 1000.0; // Convert to seconds
		throughput_mbps = (double)(local_report.bytes_received * 8) / (elapsed_time * 1000000);

		// Calculate jitter
		current_packet_time_ms = current_time;
		jitter = current_packet_time_ms - prev_packet_time_ms;
		jitter_sum_ms += jitter;
		prev_packet_time_ms = current_packet_time_ms;
	}

	if (local_report.packets_received > 1) {
		double average_jitter_ms = (double)jitter_sum_ms / (local_report.packets_received - 1);
		local_report.average_jitter = average_jitter_ms;
		local_report.elapsed_time = double_to_uint64(elapsed_time);
		local_report.throughput = double_to_uint64(throughput_mbps);
	} else
		local_report.average_jitter = 0;

	// Close the socket
	close(sockid);
	return 0;
}

int tcp_client(int num)
{
	int sockfd;
	struct sockaddr_in server_addr;
	unsigned long long start_time_ms = k_uptime_get(); //returns time in ms from the boot
	int total_duration = test_case[num].duration * 1000; //Converting into ms

	LOG_INF("TCP Client started\n");

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		printf("Failed to create socket\n");
		return -errno;
	}

	// Set server address
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_DATA_PORT);
	if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
		printf("Invalid address format\n");
		close(sockfd);
		return -errno;
	}

	// Connect to the server
	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		printf("Connection failed\n");
		close(sockfd);
		return -errno;
	}

	memset(buffer, 'A', BUFFER_SIZE);
	start_time_ms = k_uptime_get();
	while((k_uptime_get() - start_time_ms) < total_duration)
	{
		send(sockfd, buffer, test_case[num].frame_len, 0);
		k_sleep(K_MSEC(50));
	}

	/* Send empty msg to the server to indicate end of TX */
	{
		char empty_data = '\0';
		send(sockfd, &empty_data, 0, 0);
	}

	// Close the socket
	close(sockfd);

	LOG_INF("TCP Client finished\n");
	return 0;
}

int tcp_server(int num)
{
	int sockfd, new_sock, bytes;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int prev_packet_time_ms = 0, current_packet_time_ms, jitter;
	int jitter_sum_ms = 0;
	uint32_t current_time, start_time;
	double elapsed_time = 0.0, throughput_mbps = 0;

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		printf("Failed to create socket\n");
		return -errno;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_DATA_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		printf("Bind failed\n");
		close(sockfd);
		return -errno;
	}

	if (listen(sockfd, 3) < 0) {
		printf("Listen failed\n");
		close(sockfd);
		return -errno;
	}

	printf("TCP server is listening on port %d\n", SERVER_DATA_PORT);

	new_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
	if (new_sock < 0) {
		printf("Accept failed\n");
		close(sockfd);
		return -errno;
	}

	memset(&local_report, 0 , sizeof(struct server_report));

        start_time = k_uptime_get_32();
	while(1)
       	{
		bytes = recv(new_sock, buffer, BUFFER_SIZE, 0);
		if(bytes <= 0)
		{
			LOG_INF("END OF TCP RX\n");
			break;
		}

		local_report.bytes_received += bytes;
		local_report.packets_received++;

		// Calculate throughput
		current_time = k_uptime_get_32();
		elapsed_time = (double)(current_time - start_time) / 1000.0; // Convert to seconds
		//throughput_mbps = (double)(local_report.bytes_received * 8) / (elapsed_time * 1000000);

		// Calculate jitter
		current_packet_time_ms = current_time;
		jitter = current_packet_time_ms - prev_packet_time_ms;
		jitter_sum_ms += jitter;
		prev_packet_time_ms = current_packet_time_ms;
	}

	if (local_report.packets_received > 1) {
		throughput_mbps = (double)(local_report.bytes_received * 8) / (elapsed_time * 1000000);
		double average_jitter_ms = (double)jitter_sum_ms / (local_report.packets_received - 1);
		local_report.average_jitter = double_to_uint64(average_jitter_ms);
		local_report.elapsed_time = double_to_uint64(elapsed_time);
		local_report.throughput = double_to_uint64(throughput_mbps);
#if 1
		printf("Elapsed Time %0.2f Seconds\n\t",elapsed_time);
		printf("Throuhput %0.2f Mbps\n\t",throughput_mbps);
		printf("Average Jitter %0.2f ms\n\t",average_jitter_ms);
#endif
	} else
		local_report.average_jitter = 0;

	close(new_sock);
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
			udp_client(num);
			LOG_INF("Completed UDP Data Tx\n");
		} else if (test_case[num].traffic_type == TCP) {
			LOG_INF("Sending TCP Data......\n");
			tcp_client(num);
		} else {
			LOG_INF("Invalid Traffic: choose either TCP/UDP\n");
		}
	} else if(test_case[num].client_role == DOWNLINK) {
		if(test_case[num].traffic_type == UDP)
		{
			LOG_INF("UDP SERVER STARTED\n");
			udp_server(num);
			LOG_INF("FInished UDP SERVER \n");
		} else if (test_case[num].traffic_type == TCP) {
			LOG_INF("TCP SERVER STARTED\n");
			tcp_server(num);
			LOG_INF("EXIT FROM TCP SERVER\n");
		} else {
			LOG_INF("Invalid Traffic: choose either TCP/UDP\n");
		}
	}

	return 0;
}

// Function to convert network-order uint64_t to double
double network_order_to_double(uint64_t value)
{
	double result;
	uint64_t beValue = ntohll(value);

	memcpy(&result, &beValue, sizeof(double));
	return result;
}


void print_report(int client_role)
{
	struct server_report *report = (struct server_report *)report_buffer;


	if(client_role == UPLINK)
	{
	LOG_INF(" ###### REPORT ########\n\t");
		LOG_INF("UPLINK Num of Bytes Received %d\n\t",ntohl(report->bytes_received));
		LOG_INF("Num of PKTS Received %d\n\t",ntohl(report->packets_received));
		LOG_INF("Elapsed Time %.2f Seconds\n\t",network_order_to_double(report->elapsed_time));
		LOG_INF("Throuhput %.2f Mbps\n\t",network_order_to_double(report->throughput));
		LOG_INF("Average Jitter %.2f ms\n\t",network_order_to_double(report->average_jitter));
	} else {
		LOG_INF("DOWNLINK Num of Bytes Received %d\n\t",(report->bytes_received));
		LOG_INF("Num of PKTS Received %d\n\t",(report->packets_received));
#if 1
		printf("1Elapsed Time %.2f Seconds\n\t",uint64_to_double(report->elapsed_time));
		printf("2Throuhput %.2f Mbps\n\t",uint64_to_double(report->throughput));
		printf("3Average Jitter %.2f ms\n\t",uint64_to_double(report->average_jitter));
		printf("4Elapsed Time %.2f Seconds\n\t",uint64_to_double(local_report.elapsed_time));
		printf("5Throuhput %.2f Mbps\n\t",uint64_to_double(local_report.throughput));
		printf("6Average Jitter %.2f ms\n\t",uint64_to_double(local_report.average_jitter));
#endif
	}
}

int wait_for_report(int sock, int client_role)
{
	memset(report_buffer, 0, BUFFER_SIZE);

	LOG_INF("Waiting for report from the Server\n");

	/* Receive a response from the server */
	if(client_role == UPLINK)
		recv(sock, report_buffer, BUFFER_SIZE, 0);
	else
		memcpy(report_buffer, (uint8_t *)&local_report, sizeof(struct server_report));

	print_report(client_role);
	return 0;
}

int send_cmd(int sock, int num)
{
	struct cmd cf;

	cf.client_role = htonl(test_case[num].client_role);
	cf.traffic_type = htonl(test_case[num].traffic_type);
	cf.traffic_mode = htonl(test_case[num].traffic_mode);
	cf.duration = htonl(test_case[num].duration);
	cf.frame_len = htonl(test_case[num].frame_len);
	cf.reserved = 0;
	send(sock, &cf, sizeof(struct cmd), 0);
	printf("Control frame sent to server\n");

	return 0;
}

void start_test(int num)
{
	/* send cmd to the server */
	LOG_INF("Sending CMD to the Client\n");
	send_cmd(ctrl_sock_fd, num);

	k_sleep(K_SECONDS(1));

	/* Function to send/receive data frames based on the test case num */
	send_receive_data_frames(num);

	/* Function to receive the report from the server */
	wait_for_report(ctrl_sock_fd, test_case[num].client_role);
}

/* handling control messages with server like start/stop/report */
int init_tcp() 
{
	struct sockaddr_in serv_addr;

	LOG_INF("Connected To Server!!! \n");
	/* Create socket */
	if ((ctrl_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_INF("Socket creation failed");
		return -errno;
	}

	LOG_INF("Connected To Server!!! \n");
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERVER_CTRL_PORT);

	LOG_INF("Connected To Server!!! \n");
	/* Convert IPv4 and IPv6 addresses from text to binary form */
	if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
		LOG_INF("Invalid address/ Address not supported");
		return -errno;
	}

	LOG_INF("Connected To Server!!! \n");
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

#if ENABLE_KTHREADS
	k_sem_init(&start_client_sem, 0, 1);
	k_sem_init(&start_server_sem, 0, 1);
	k_thread_create(&udp_client_thread, thread_stack1, STACK_SIZE,
                    udp_client, NULL, NULL, NULL,
                    THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_create(&udp_server_thread, thread_stack2, STACK_SIZE,
                    udp_server, NULL, NULL, NULL,
                    THREAD_PRIORITY, 0, K_NO_WAIT);
#endif

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

			LOG_INF("\n#### PS MODE: DTIM ### \n");
			/* run the test cases uplink/downlink/both */
			for(test_case_no = 0; test_case_no<CURR_TEST_CASE_CNT; test_case_no++)
			{
				LOG_INF("TEST_CASE: %d\n", test_case_no);
				start_test(test_case_no);
				LOG_INF("TEST CASE: %d Completed\n", test_case_no);
				k_sleep(K_SECONDS(10));
			}
#if ENABLE_TWT
			setupTWT();
#endif
			k_sleep(K_MSEC(1000));
			LOG_INF("Releasing client and server sem\n");
#if ENABLE_KTHREADS
			k_sem_give(&start_client_sem);
			k_sem_give(&start_server_sem);
#endif

			LOG_INF("END of APP\n");
			k_sleep(K_FOREVER);
		} else if (!context.connect_result) {
			LOG_ERR("Connection Timed Out");
		}
	}

	return 0;
}
