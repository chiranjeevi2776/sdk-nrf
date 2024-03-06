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

#ifdef CONFIG_NET_CONFIG_SETTINGS
#include <zephyr/net/net_config.h>
#endif

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

static int wifi_set_channel(void)
{
	struct net_if *iface;
	struct wifi_channel_info channel_info = { 0 };
	int ret;

	channel_info.oper = WIFI_MGMT_SET;

	iface = net_if_get_first_wifi();
	if (iface == NULL) {
		LOG_ERR("No Wi-Fi interface found");
		return -1;
	}

	channel_info.if_index = net_if_get_by_iface(iface);
	channel_info.channel = CONFIG_PROMISCUOUS_MODE_CHANNEL;
	if ((channel_info.channel < WIFI_CHANNEL_MIN) ||
	    (channel_info.channel > WIFI_CHANNEL_MAX)) {
		LOG_ERR("Invalid channel number %d. Range is %d-%d",
			channel_info.channel, WIFI_CHANNEL_MIN, WIFI_CHANNEL_MAX);
		return -1;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_CHANNEL, iface,
		       &channel_info, sizeof(channel_info));
	if (ret) {
		LOG_ERR(" Channel setting failed %d Channel %d\n", ret, channel_info.channel);
		return -1;
	}

	LOG_INF("Wi-Fi channel set to %d for interface %d",
		channel_info.channel, channel_info.if_index);

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

#ifdef CONFIG_NET_CONFIG_SETTINGS
	/* Without this, DHCPv4 starts on first interface and if that is not Wi-Fi or
	 * only supports IPv6, then its an issue. (E.g., OpenThread)
	 *
	 * So, we start DHCPv4 on Wi-Fi interface always, independent of the ordering.
	 */
	/* TODO: Replace device name with DTS settings later */
	const struct device *dev = device_get_binding("wlan0");
	struct net_if *wifi_iface = net_if_lookup_by_dev(dev);

	/* As both are Ethernet, we need to set specific interface*/
	net_if_set_default(wifi_iface);

	net_config_init_app(dev, "Initializing network");
#endif

	ret = wifi_set_mode();
	if (ret) {
		return -1;
	}

	ret = wifi_set_reg();
	if (ret) {
		return -1;
	}

	ret = wifi_set_channel();
	if (ret) {
		return -1;
	}

	return 0;
}
