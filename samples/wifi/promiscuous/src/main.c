/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief Wi-Fi Promiscuous sample
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/wifi_mgmt.h>
LOG_MODULE_REGISTER(promiscuous, CONFIG_LOG_DEFAULT_LEVEL);

#include "wifi_connection.h"

#define ENABLE_PROMISCUOUS_MODE 1
#define DISABLE_PROMISCUOUS_MODE 0

static int wifi_set_reg(void)
{
	struct net_if *iface;
	struct wifi_reg_domain reg = { 0 };
	int ret;

	reg.oper = WIFI_MGMT_SET;

	iface = net_if_get_first_wifi();
	if (iface == NULL) {
		LOG_ERR("No Wi-Fi interface found");
		return -1;
	}

	reg.country_code[0] = CONFIG_PROMISCUOUS_MODE_REG_DOMAIN_ALPHA2[0];
	reg.country_code[1] = CONFIG_PROMISCUOUS_MODE_REG_DOMAIN_ALPHA2[1];
	reg.force = false;

	ret = net_mgmt(NET_REQUEST_WIFI_REG_DOMAIN, iface, &reg, sizeof(reg));
	if (ret) {
		LOG_ERR("Regulatory setting failed %d", ret);
		return -1;
	}

	LOG_INF("Regulatory set to %c%c for interface %d", reg.country_code[0],
		reg.country_code[1], net_if_get_by_iface(iface));

	return 0;
}

static int wifi_set_mode(void)
{
	int ret;
	struct net_if *iface;
	bool mode_val = ENABLE_PROMISCUOUS_MODE;

	iface = net_if_get_first_wifi();
	if (iface == NULL) {
		LOG_ERR("No Wi-Fi interface found");
		return -1;
	}

	ret = net_eth_promisc_mode(iface, mode_val);
	if (ret) {
		LOG_ERR("Promiscuous mode %s failed", mode_val ? "enabling" : "disabling");
		return -1;
	}

	LOG_INF("Interface (%d) now setup in Wi-Fi promiscuous mode", net_if_get_by_iface(iface)); 

	return 0;
}

int main(void)
{
	int ret;

	ret = wifi_set_mode();
	if (ret) {
		return -1;
	}

	ret = wifi_set_reg();
	if (ret) {
		return -1;
	}

	ret = try_wifi_connect();
	if (ret < 0) {
		return ret;
	}

	return 0;
}
