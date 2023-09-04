
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

void traffic_gen_get_report(struct traffic_gen_config *tg_config)
{
	struct server_report *report = (struct server_report *)report_buffer;

	if (tg_config->role == TWT_CLIENT) {
		if(!tg_config->server_report_received) {
			memcpy(report_buffer, (uint8_t *)&twt_client_report, sizeof(struct server_report));
			LOG_INF("Server Report not received");
			LOG_INF("Printing Client Report:");
		} else {
			LOG_INF("Server Report:");
		}
		LOG_INF("\t Total Bytes Received  : %-15u", ntohl(report->bytes_received));
		LOG_INF("\t Total Packets Received: %-15u", ntohl(report->packets_received));
		LOG_INF("\t Elapsed Time          : %-15u", ntohl(report->elapsed_time));
		LOG_INF("\t Throughput (Kbps)     : %-15u", ntohl(report->throughput));
		LOG_INF("\t Average Jitter (ms)   : %-15u", ntohl(report->average_jitter));
	} else {
		LOG_INF("Client Report:");
		LOG_INF("\t Total Bytes Received  : %-15u", (report->bytes_received));
		LOG_INF("\t Total Packets Received: %-15u", (report->packets_received));
		LOG_INF("\t Elapsed Time          : %-15u", (report->elapsed_time));
		LOG_INF("\t Throughput (Kbps)     : %-15u", (report->throughput));
		LOG_INF("\t Average Jitter (ms)   : %-15u", (report->average_jitter));
	}
}

int traffic_gen_wait_for_report(struct traffic_gen_config *tg_config)
{
	int ret = 0, bytes_received = 0;
	struct timeval timeout;

	tg_config->server_report_received = 0;
	memset(report_buffer, 0, REPORT_BUFFER_SIZE);

	LOG_INF("Waiting for report from the Server");

	/* Wait for a response upto the REPORT_TIMEOUT from the server */
	timeout.tv_sec = REPORT_TIMEOUT;
	timeout.tv_usec = 0;

	ret = setsockopt(tg_config->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (ret < 0) {
		LOG_ERR("Failed to set socket option");
		return -errno;
	}

	if (tg_config->role == TWT_CLIENT) {
		bytes_received = recv(tg_config->ctrl_sock_fd, report_buffer, REPORT_BUFFER_SIZE, 0);
	} else {
		memcpy(report_buffer, (uint8_t *)&twt_client_report, sizeof(struct server_report));
	}

	if (bytes_received > 0) {
		LOG_INF("Received server report");
		tg_config->server_report_received = 1;
	} else if (bytes_received == 0) {
		LOG_INF("Server report not received and connection closed by peer");
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		LOG_INF("Timeout: Server report not received within %d seconds", REPORT_TIMEOUT);
	} else {
		LOG_INF("Server report recv failed: %d", errno);
	}

	close(tg_config->ctrl_sock_fd);

	return 0;
}

static int connect_to_twt_server(struct traffic_gen_config *tg_config)
{
	struct sockaddr_in serv_addr;
	int sockfd;

	/* Create control path socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
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
	k_sleep(K_SECONDS(3));

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
	k_sleep(K_SECONDS(5));

	/* Create data path socket for uplink/downlink traffic */
	ret = setup_data_path(tg_config);
	if (ret < 0) {
		LOG_INF("Failed to setup data path");
		return -1;
	}

	ret = process_traffic(tg_config);

	return 0;
}

void traffic_gen_init(struct traffic_gen_config *tg_config)
{
	memset((unsigned char *)tg_config, 0, sizeof(struct traffic_gen_config));

#ifdef CONFIG_WIFI_TWT_CLIENT
	tg_config->role = TWT_CLIENT;
	LOG_INF("TWT APP ROLE: Client");
#elif CONFIG_WIFI_TWT_SERVER
	tg_config->role = TWT_SERVER;
	LOG_INF("TWT APP ROLE: Server");
#else
	LOG_INF("Configure TWT app as either client/server");
	return;
#endif

	tg_config->type = CONFIG_WIFI_TWT_TCP;
	tg_config->mode = CONFIG_WIFI_TWT_MODE;
	tg_config->duration = CONFIG_WIFI_TWT_TEST_DURATION;
	tg_config->payload_len = CONFIG_WIFI_TWT_PAYLOAD_SIZE;
	tg_config->server_ip = CONFIG_WIFI_TWT_SERVER_IPV4_ADDR;
	tg_config->port = CONFIG_WIFI_TWT_SERVER_PORT_NUM;

}
