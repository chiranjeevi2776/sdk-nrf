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

#define BUFFER_SIZE CONFIG_WIFI_TWT_PAYLOAD_SIZE
#define MAX_EMPTY_MSG_LOOP_CNT 5

struct server_report local_report;

int init_tcp_client(struct traffic_gen_config *tg_config)
{
	int sockfd = 0;

	/* Create tcp socket */
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		LOG_ERR("Failed to create tcp client socket %d", errno);
		return -errno;
	}

	return sockfd;
}

int send_tcp_uplink_traffic(struct traffic_gen_config *tg_config)
{
	char empty_data = '\0';
	int ret = 0;
	unsigned long long start_time_ms;
	struct sockaddr_in server_addr;
	int total_duration = tg_config->duration * 1000; /* Converting into ms */

	/* Set server address */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(tg_config->port);
	if (inet_pton(AF_INET, tg_config->server_ip, &server_addr.sin_addr) <= 0) {
		LOG_ERR("Invalid IPV4 address format");
		close(tg_config->data_sock_fd);
		return -errno;
	}

	/* Connect to the server */
	ret = connect(tg_config->data_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		LOG_ERR("Cannot coonect TCP remote (%s): %d\n", tg_config->server_ip, errno);
		close(tg_config->data_sock_fd);
		return -errno;
	}

	LOG_INF("Sending TCP uplink Traffic");

	memset(tg_config->buffer, 'A', BUFFER_SIZE);
	/* returns time in ms from the boot */
	start_time_ms = k_uptime_get();

	while ((k_uptime_get() - start_time_ms) < total_duration) {
		/* send(tg_config->data_sock_fd, tg_config->buffer, tg_config->payload_len, 0); */
		send(tg_config->data_sock_fd, tg_config->buffer, 100, 0);
		k_sleep(K_MSEC(300));
		/* k_sleep(K_SECONDS(1)); */ /* 9999 */
	}

	/* Send empty msg to the server to indicate end of TX */
	k_sleep(K_SECONDS(1));
	for (int i = 0; i <= MAX_EMPTY_MSG_LOOP_CNT; i++) {
		ret = send(tg_config->data_sock_fd, &empty_data, 0, 0);
		if (ret < 0) {
			LOG_ERR("Failed to send TWT config info to TWT server %d", errno);
			return -errno;
		}
		k_sleep(K_MSEC(100));
	}

	/* Close data socket */
	close(tg_config->data_sock_fd);

	LOG_INF("Sent TCP uplink traffic for %d sec", tg_config->duration);

	return 0;
}

int init_tcp_server(struct traffic_gen_config *tg_config)
{
	int sockfd = 0;
	struct sockaddr_in server_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		LOG_ERR("Failed to create tcp server socket %d", errno);
		return -errno;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(tg_config->port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		LOG_ERR("Bind failed");
		close(sockfd);
		return -errno;
	}

	return sockfd;
}

int recv_tcp_downlink_traffic(struct traffic_gen_config *tg_config)
{
	int sockfd, bytes;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int prev_packet_time_ms = 0, current_packet_time_ms, jitter;
	int jitter_sum_ms = 0;
	uint32_t current_time, start_time;
	double elapsed_time = 0.0, throughput_mbps = 0;

	if (listen(tg_config->data_sock_fd, 3) < 0) {
		LOG_ERR("Failed to listen on TCP socket %d", errno);
		close(tg_config->data_sock_fd);
		return -errno;
	}

	LOG_INF("TCP server is listening on port %d", tg_config->port);

	sockfd = accept(tg_config->data_sock_fd, (struct sockaddr *)&client_addr, &client_addr_len);
	if (sockfd < 0) {
		LOG_INF("Accept failed\n");
		close(tg_config->data_sock_fd);
		return -errno;
	}

	memset(&local_report, 0 , sizeof(struct server_report));

        start_time = k_uptime_get_32();
	while (1) {
		bytes = recv(sockfd, tg_config->buffer, BUFFER_SIZE, 0);
		if (bytes <= 0) {
			LOG_INF("Finished TCP downlink traffic ");
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

		LOG_INF("Elapsed Time %0.2f Seconds",elapsed_time);
		LOG_INF("Throuhput %0.2f Mbps",throughput_mbps);
		LOG_INF("Average Jitter %0.2f ms",average_jitter_ms);
	} else {
		local_report.average_jitter = 0;
	}

	close(sockfd);
	return 0;
}
