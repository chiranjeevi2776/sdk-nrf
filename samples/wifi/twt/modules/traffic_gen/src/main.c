
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(twt, CONFIG_LOG_DEFAULT_LEVEL);

#include <nrfx_clock.h>
#include <zephyr/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>
#include <zephyr/init.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/drivers/gpio.h>

#include "net_private.h"
#include <zephyr/net/socket.h>
#include "traffic_gen.h"

#define TWT_CTRL_PORT 6666
#define REPORT_BUFFER_SIZE 100
#define REPORT_TIMEOUT 20

unsigned char report_buffer[REPORT_BUFFER_SIZE];

uint64_t double_to_uint64(double value)
{
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

/* Function to convert network-order uint64_t to double */
double network_order_to_double(uint64_t value)
{
	double result;
	uint64_t beValue = ntohll(value);

	memcpy(&result, &beValue, sizeof(double));
	return result;
}

void print_report(struct traffic_gen_config *tg_config)
{
	struct server_report *report = (struct server_report *)report_buffer;

	if(tg_config->role == TWT_CLIENT)
	{
		k_sleep(K_SECONDS(5));
		LOG_INF("\n");
		LOG_INF("|             Server Report                  |\n");
		LOG_INF("|-------------------------------------------|\n");
		LOG_INF("| Total Bytes Received  : %-15u |\n",ntohl(report->bytes_received));
		LOG_INF("| Total Packets Received: %-15u |\n",ntohl(report->packets_received));
		LOG_INF("| Total Elapsed Time    : %-15u |\n",ntohl(report->packets_received));
		LOG_INF("| Throughput (Mbps)     : %-15.2f |\n",network_order_to_double(report->throughput));
		LOG_INF("| Elapsed Time          : %-15.2f |\n",network_order_to_double(report->elapsed_time));
		LOG_INF("=============================================\n");
#if 0
	        /* Make sure LOG_INF will not print floating values */
		printf("UPLINK Num of Bytes Received %d\n\t",ntohl(report->bytes_received));
		printf("Num of PKTS Received %d\n\t",ntohl(report->packets_received));
		printf("Elapsed Time %f Seconds\n\t",network_order_to_double(report->elapsed_time));
		printf("Throuhput %f Mbps\n\t",network_order_to_double(report->throughput));
		printf("Average Jitter %f ms\n\t",network_order_to_double(report->average_jitter));
#endif
	} else {
		LOG_INF(" ###### DOWNLINK REPORT ########\n\t");
		k_sleep(K_SECONDS(5));
		LOG_INF("DOWNLINK Num of Bytes Received %d\n\t",(report->bytes_received));
		LOG_INF("Num of PKTS Received %d\n\t",(report->packets_received));
		LOG_INF("1Elapsed Time %.2f Seconds\n\t",uint64_to_double(report->elapsed_time));
		LOG_INF("2Throuhput %.2f Mbps\n\t",uint64_to_double(report->throughput));
		LOG_INF("3Average Jitter %.2f ms\n\t",uint64_to_double(report->average_jitter));
	}
}

int wait_for_report(struct traffic_gen_config *tg_config)
{
	int ret = 0, bytes_received = 0;
	struct timeval timeout;

	memset(report_buffer, 0, REPORT_BUFFER_SIZE);

	LOG_INF("Waiting for report from the Server\n");

	/* Wait for a response upto the REPORT_TIMEOUT from the server */
	timeout.tv_sec = REPORT_TIMEOUT;
	timeout.tv_usec = 0;
#if 1 /* 9999 */
	ret = setsockopt(tg_config->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (ret < 0) {
		LOG_ERR("Failed to set socket option");
		return -errno;
	}
#endif

	if (tg_config->role == TWT_CLIENT) {
		bytes_received = recv(tg_config->ctrl_sock_fd, report_buffer, REPORT_BUFFER_SIZE, 0);
	} else {
		memcpy(report_buffer, (uint8_t *)&local_report, sizeof(struct server_report));
	}

	if (bytes_received > 0) {
		LOG_INF("Received server report"); 
	} else if (bytes_received == 0) {
		LOG_INF("Server report not received and connection closed by peer");
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		LOG_INF("Timeout: Server report not received within %d seconds", REPORT_TIMEOUT);
	} else {
		LOG_INF("Server report recv failed: %d", errno);
	}	

	print_report(tg_config);

	return 0;
}

static int connect_to_twt_server(struct traffic_gen_config *tg_config)
{
	struct sockaddr_in serv_addr;
	int sockfd;

	/* Create control path socket */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_INF("Failed to create control path socket");
		return -errno;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(TWT_CTRL_PORT);

	/* Convert IPv4 addresses from text to binary form */
	if (inet_pton(AF_INET, tg_config->server_ip, &serv_addr.sin_addr) <= 0) {
		LOG_INF("Invalid address: Address not supported");
		close(sockfd);
		return -errno;
	}

	/* Connect to the TWT server */
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		LOG_INF("Failed to connect TWT server");
		LOG_INF("Run the TWT server in other end before running TWT app");
		close(sockfd);
		return -errno;
	}

	LOG_INF("Connected To TWT Server!!!");
	k_sleep(K_SECONDS(10));

	return sockfd;
}

static int send_config_info_to_twt_server(struct traffic_gen_config *tg_config)
{
	int ret;
	struct twt_server_config config;

	config.role = htonl(tg_config->role);
	config.type = htonl(tg_config->type);
	config.mode = htonl(tg_config->mode);
	config.duration = htonl(tg_config->duration);
	config.payload_len = htonl(tg_config->payload_len);

	ret = send(tg_config->ctrl_sock_fd, &config, sizeof(struct twt_server_config), 0);
	if (ret < 0) {
		LOG_ERR("Failed to send TWT config info to TWT server %d", errno);
		return -errno;
	}

	LOG_INF("Config info sent to the TWT server");

	return 1;
}

static int setup_ctrl_path(struct traffic_gen_config *tg_config)
{
	int ret;

	/* Connect to TWT server:
	 *  - send config info from TWT client to TWT server
	 *  - configure TWT server, as per config info from TWT client
	 *  - after traffic completeion wait for the TWT server report
	 */  
	ret = connect_to_twt_server(tg_config);
	if (ret < 0) {
		return -1;
	}

	tg_config->ctrl_sock_fd = ret;

	/* send config info to twt server */
	ret = send_config_info_to_twt_server(tg_config);
	if (ret < 0) {
		return -1;
	}

	return 1;
}

/* Create uplink/downlink datapath socket */
static int setup_data_path(struct traffic_gen_config *tg_config)
{
	int ret = 0;

	if (tg_config->role == TWT_CLIENT) {
		if (tg_config->type == TWT_TCP) {
			ret = init_tcp_client(tg_config);
			if (ret < 0) {
				return -1;
			}
			tg_config->data_sock_fd = ret;
		} else {
			LOG_INF("Failed to setup traffic type");
			return 1;
		}
	} else if (tg_config->role == TWT_SERVER) {
		if (tg_config->type == TWT_TCP) {
			ret = init_tcp_server(tg_config);
			if (ret < 0) {
				return -1;
			}
			tg_config->data_sock_fd = ret;
		} else {
			LOG_INF("Failed to setup traffic type");
			return -1;
		}
	} else {
		LOG_INF("Failed to setup TWT role as Client/Server");
		return -1;
	}

	return 1;
}

static int process_traffic(struct traffic_gen_config *tg_config)
{
	int ret = 0;

	if (tg_config->role == TWT_CLIENT) {
		if (tg_config->type == TWT_TCP) {
			ret = send_tcp_uplink_traffic(tg_config);
			if (ret < 0) {
				return -1;
			}
		} else {
			LOG_INF("Failed to setup traffic type");
			return -1;
		}
	} else if (tg_config->role == TWT_SERVER) {
		if (tg_config->type == TWT_TCP) {
			ret = recv_tcp_downlink_traffic(tg_config);
			if (ret < 0) {
				return -1;
			}
		} else {
			LOG_INF("Failed to setup traffic type");
			return -1;
		}
	} else {
		LOG_INF("Failed to setup TWT role as Client/Server");
		return 1;
	}

	return 1;
}

int traffic_gen_start(struct traffic_gen_config *tg_config)
{
	int ret;

	/* Create control path socket */
	ret = setup_ctrl_path(tg_config);
	if (ret < 0) {
		LOG_INF("Failed to setup control path");
		return -1;
	}

	/* Wait for server configuration 
	 *  - could be client mode
	 *  - could be server mode
	 *  - server will create data socket
	 *  - do uplink/downlink traffic based traffic configuration 
	 */
	k_sleep(K_SECONDS(10));

	/* Create data path socket for uplink/downlink traffic */
	ret = setup_data_path(tg_config);
	if (ret < 0) {
		LOG_INF("Failed to setup data path");
		return -1;
	}

	ret = process_traffic(tg_config);

	wait_for_report(tg_config); /* 9999 */

	return 0;
}

void traffic_gen_init(struct traffic_gen_config *tg_config)
{
	memset((unsigned char *)tg_config, 0, sizeof(struct traffic_gen_config));

	if (IS_ENABLED(CONFIG_WIFI_TWT_CLIENT)) {
		tg_config->role = TWT_CLIENT;
		LOG_INF("TWT APP ROLE: Client");
	} else if (IS_ENABLED(CONFIG_WIFI_TWT_SERVER)) {
		tg_config->role = TWT_SERVER;
		LOG_INF("TWT APP ROLE: Server");
	} else {
		LOG_INF("Configure TWT app as either client/server");
		return;
	}

	tg_config->type = CONFIG_WIFI_TWT_TCP;
	tg_config->mode = 1;//CONFIG_WIFI_TWT_MODE;
	tg_config->duration = CONFIG_WIFI_TWT_TEST_DURATION;
	tg_config->payload_len = CONFIG_WIFI_TWT_PAYLOAD_SIZE;
	tg_config->server_ip = CONFIG_WIFI_TWT_SERVER_IPV4_ADDR;
	tg_config->port = CONFIG_WIFI_TWT_SERVER_PORT_NUM;

	return;
}
