#ifndef TRFFIC_GEN_H
#define TRAFFIC_GEN_H


#define TWT_UDP 1
#define TWT_TCP 2

#define TWT_CLIENT 1
#define TWT_SERVER 2

struct traffic_gen_config {
	/* global info */
	int ctrl_sock_fd;
	int data_sock_fd;
	char buffer[CONFIG_WIFI_TWT_PAYLOAD_SIZE];

	/* Kconfig info */
	int role;
	int type;
	int mode;
	int duration;
	int payload_len;
	const unsigned char *server_ip;
	int port;
};

struct twt_server_config {
	int role;
	int type;
	int mode;
	int duration;
	int payload_len;
};

struct server_report {
	int bytes_received;
	int packets_received;
	int elapsed_time;
	int throughput;
	int average_jitter;
};

extern struct server_report twt_client_report;

/* traffic gen module */
void traffic_gen_init(struct traffic_gen_config *);
int traffic_gen_start(struct traffic_gen_config *);
int traffic_gen_wait_for_completion(struct traffic_gen_config *);

/* tcp client/server function prototypes */
int init_tcp_client(struct traffic_gen_config *tg_config);
int send_tcp_uplink_traffic(struct traffic_gen_config *tg_config);
int init_tcp_server(struct traffic_gen_config *tg_config);
int recv_tcp_downlink_traffic(struct traffic_gen_config *tg_config);


uint64_t double_to_uint64(double value);
double uint64_to_double(uint64_t value);

#endif
