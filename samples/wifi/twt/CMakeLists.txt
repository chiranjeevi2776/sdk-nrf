#
# Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nrf_wifi_twt)

set(COMMON_ROOT ${ZEPHYR_NRF_MODULE_DIR}/samples/wifi/twt)

target_include_directories(app PUBLIC ${ZEPHYR_BASE}/subsys/net/ip)
target_include_directories(app PRIVATE ${COMMON_ROOT}/modules/traffic_gen/inc)

target_sources(app PRIVATE
	src/main.c
	modules/traffic_gen/src/main.c
	modules/traffic_gen/src/tcp/tcp.c
)
