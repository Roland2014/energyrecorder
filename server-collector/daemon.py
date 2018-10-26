#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""data-collector daemon main code."""
# --------------------------------------------------------
# Module Name : terraHouat  power recording ILO daemon
# Version : 1.1
#
# Software Name : Open NFV functest
# Version :
#
# Copyright © 2017 Orange
# This software is distributed under the Apache 2 license
# <http://www.apache.org/licenses/LICENSE-2.0.html>
#
# -------------------------------------------------------
# File Name   : iloCollector.py
#
# Created     : 2017-02
# Authors     : Benoit HERARD <benoit.herard(at)orange.com>
#
# Description :
#     Daemon implementation
# -------------------------------------------------------
# History     :
# 1.0.0 - 2017-02-20 : Release of the file
# 1.1.0 - 2018-10-26 : Add feature to synchronize polling of different threads
##
import logging.config
import traceback
import time
import signal
import sys
import yaml
import threading

from ilocollector import ILOCollector
from ilo_gui_collector import ILOGUICollector
from idrac8_gui_collector import IDRAC8GUICollector
from intel_gui_collector import INTELGUICollector
from ibmc_gui_collector import IBMCGUICollector
from ipmicollector import IPMICollector
from redfishcollector import RedfishCollector


def signal_term_handler():
    """Sigterm signal handler."""
    for running_thread in SERVER_THREADS:
        msg = "Stopping thread for server {}".format(collector.server_id)
        LOG.info(msg)
        running_thread.stop()
    LOG.info("Please wait....")
    if syncpolling_interval != -1:
        # set condition in order to release thread if there were
        # waiting to enable them to stop
        condition.acquire()
        condition.notifyAll()
        condition.release()
    for running_thread in SERVER_THREADS:
        running_thread.join()
    LOG.info("Program terminated")


# Activate signal handler for SIGTERM
signal.signal(signal.SIGTERM, signal_term_handler)
# Create running thead list object
SERVER_THREADS = []
# Init conditional semaphore to synchronize polling thread
condition = threading.Condition()
# -1 means not synchornized polling (default behaviour)
group_syncpolling_interval = -1

# Configure logging
logging.config.fileConfig("conf/collector-logging.conf")
LOG = logging.getLogger(__name__)

LOG.info("Server power consumption daemon is starting")
with open("conf/collector-settings.yaml", 'r') as stream:
    try:
        CONFIG = yaml.load(stream)
        # print(conf["PODS"])
    except yaml.YAMLError as exc:
        LOG.exception("Error while loading config")
        sys.exit()

for pod in CONFIG["PODS"]:
    log_msg = "Starting collector threads for pod {}"
    log_msg = log_msg.format(pod["environment"])
    LOG.info(log_msg)

    for sync_group in pod["syncgroup"]:
        if sync_group["name"] != "default":
            syncpolling_interval = sync_group["group_syncpolling_interval"]
            log_msg = "\tStarting threads with synchronized polling of {}s"
            log_msg += " for group {}"
            log_msg = log_msg.format(syncpolling_interval, sync_group["name"])
            LOG.info(log_msg)

        for server in sync_group["servers"]:
            log_msg = "\tStarting thread collector for server {}"
            log_msg = log_msg.format(server["id"])
            LOG.info(log_msg)
            if server["type"] == "ilo":
                if syncpolling_interval != -1:
                    log_msg = "Synchronized polling ignored as not supported"
                    log_msg += " for this connector type"
                    LOG.info(log_msg)

                ilo_server_conf = {
                    "base_url": "https://{}".format(server["host"]),
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]

                }
                collector = ILOCollector(pod["environment"],
                                         server["id"],
                                         ilo_server_conf,
                                         CONFIG["RECORDER_API_SERVER"])
            elif server["type"] == "ilo-gui":
                if syncpolling_interval != -1:
                    log_msg = "Synchronized polling ignored as not supported"
                    log_msg += " for this connector type"
                    LOG.info(log_msg)

                ilo_server_conf = {
                    "base_url": "https://{}".format(server["host"]),
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]

                }
                collector = ILOGUICollector(pod["environment"],
                                            server["id"],
                                            ilo_server_conf,
                                            CONFIG["RECORDER_API_SERVER"])

            elif server["type"] == "idrac8-gui":
                if syncpolling_interval != -1:
                    log_msg = "Synchronized polling ignored as not supported"
                    log_msg += " for this connector type"
                    LOG.info(log_msg)

                idrac_server_conf = {
                    "base_url": "https://{}".format(server["host"]),
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]

                }
                collector = IDRAC8GUICollector(pod["environment"],
                                               server["id"],
                                               idrac_server_conf,
                                               CONFIG["RECORDER_API_SERVER"])

            elif server["type"] == "intel-gui":
                if syncpolling_interval != -1:
                    log_msg = "Synchronized polling ignored as not supported"
                    log_msg += " for this connector type"
                    LOG.info(log_msg)

                intel_server_conf = {
                    "base_url": "https://{}".format(server["host"]),
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]

                }
                collector = INTELGUICollector(pod["environment"],
                                              server["id"],
                                              intel_server_conf,
                                              CONFIG["RECORDER_API_SERVER"])

            elif server["type"] == "ibmc-gui":
                if syncpolling_interval != -1:
                    log_msg = "Synchronized polling ignored as not supported"
                    log_msg += " for this connector type"
                    LOG.info(log_msg)

                ibmc_server_conf = {
                    "base_url": "https://{}".format(server["host"]),
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]

                }
                collector = IBMCGUICollector(pod["environment"],
                                             server["id"],
                                             ibmc_server_conf,
                                             CONFIG["RECORDER_API_SERVER"])

            elif server["type"] == "redfish":
                ilo_server_conf = {
                    "base_url": "https://{}".format(server["host"]),
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]

                }
                collector = RedfishCollector(
                    pod["environment"],
                    server["id"],
                    ilo_server_conf,
                    CONFIG["RECORDER_API_SERVER"],
                    condition,
                    sync_group["name"])
            elif server["type"] == "ipmi":
                ipmi_server_conf = {
                    "host": server["host"],
                    "user": server["user"],
                    "pass": server["pass"],
                    "polling_interval": server["polling_interval"]
                }

                collector = IPMICollector(pod["environment"],
                                          server["id"],
                                          ipmi_server_conf,
                                          CONFIG["RECORDER_API_SERVER"],
                                          condition,
                                          sync_group["name"])
            else:
                MSG = "Unsupported power collect method: {}"
                MSG += MSG.format(server["type"])
                raise Exception(MSG)

            SERVER_THREADS.append(collector)
            collector.start()

try:
    while True:
        # Wait for ever unless we receive a SIGTEM (see signal_term_handler)
        if syncpolling_interval != -1:
            # Synchronized polling
            LOG.info("Notify all thread to collect")

            condition.acquire()
            condition.notify_all()
            condition.release()

            time.sleep(syncpolling_interval)
        else:
            # thread autonomous polling without synchronization
            time.sleep(1)
except KeyboardInterrupt:
    signal_term_handler()
except SystemExit:
    pass
except Exception:  # pylint: disable=locally-disabled,broad-except
    MSG = "Unexpected error: {}".format(traceback.format_exc())
    LOG.error(MSG)
    signal_term_handler()

# Wait for the end of running threads
for thread in SERVER_THREADS:
    thread.join()
