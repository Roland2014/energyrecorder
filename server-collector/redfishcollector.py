# -*- coding: UTF-8 -*-
# --------------------------------------------------------
# Module Name : terraHouat  power recording Redfish daemon
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
# File Name   : RedfishCollector.py
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
#

"""Collect power comsumption via redfish API."""

import logging.config
import time
import json
import sys
import traceback
from threading import Thread
import requests
from common import DataPoster

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


class RedfishCollector(Thread):
    """Collect power consumption via HP Redfish rest/redfish API."""

    def __init__(self,
                 environment,
                 server_id,
                 redfish_server_conf,
                 data_server_conf,
                 condition,
                 sync_group):
        """
        Constructor: create an instance of IPMICollector class.

            :param environment: Environment on witch power is collected
            :type environment: string

            :param server_id: Server identifier
            :type server_id: string

            :param redfish_server_conf: Dictionnatry containing Redfish API
                                    connectivity settings
            :type server_base_url: dictionary
            {
                "base_url": "Redfish API base URL. Ex.: https://localhost:443",
                "user": Basic authentication user,
                "pass": Basic authentication password
                "polling_interval": polling interval diration
            }

            :param data_server_conf: recorder API connection params
            :type data_server_conf dictionarydictionary
            {
                "base_url": "Recorder API base URL",
                "user": Basic authentication user,
                "pass": Basic authentication password
            }

            :param condition: Synchronisation object between thread
            :type condition: conditional semaphore

            :param sync_group: Synchronisation group the thread belongs to
            :type sync_group: string
        """
        Thread.__init__(self)
        self.server_id = server_id
        self.redfish_server_conf = redfish_server_conf
        self.environment = environment
        if redfish_server_conf["user"] != "" and\
           redfish_server_conf["pass"] != "":
            self.pod_auth = (
                redfish_server_conf["user"], redfish_server_conf["pass"])
        else:
            self.pod_auth = None
        self.data_server_conf = data_server_conf
        self.condition = condition
        self.sync_group = sync_group
        self.running = False
        self.log = logging.getLogger(__name__)

    def _is_https(self,):
        """Try to determine if host is using https or not."""

        try:
            url = self.redfish_server_conf["base_url"]
            self.log.debug("trying to call %s", url)
            requests.get(url, verify=False)
            return True
        except requests.exceptions.ConnectionError:
            url = url.replace("https", "http")
            self.log.debug("trying to call %s", url)
            requests.get(url)
            return False

    def stop(self):
        """
        Stop running Thread.

        Request to the current thread to stop by the end
        of current loop iteration
        """
        log_msg = "Stop called for server {} of group {}"
        log_msg = log_msg.format(self.server_id, self.sync_group)
        self.log.debug(log_msg)
        self.running = False

    def load_chassis_list(self):
        """Get Chassis List for server Redfish API."""
        chassis_list = None

        # Get Chassis list
        while chassis_list is None and self.running:
            try:
                request_url = self.redfish_server_conf["base_url"]
                request_url += "/redfish/v1/Chassis/"
                response = requests.get(request_url,
                                        auth=self.pod_auth,
                                        verify=False)
                self.log.debug(
                    "Chassis list at %s ",
                    request_url
                )
                if response.status_code != 200:
                    self.log.error(
                        "Error while calling %s\nHTTP STATUS=%d\nHTTP BODY=%s",
                        request_url,
                        response.status_code,
                        response.text
                    )
                    self.running = False
                else:
                    chassis_list = json.loads(response.text)
            except Exception:  # pylint: disable=locally-disabled,broad-except
                log_msg = "Error while trying to connect server {} ({}): {}"
                log_msg = log_msg.format(self.server_id,
                                         self.redfish_server_conf["base_url"],
                                         sys.exc_info()[0])
                self.log.error(log_msg)
                self.log.debug(traceback.format_exc())
                time.sleep(5)
        return chassis_list

    def get_power(self, chassis_uri):
        """Get PowerMetter values form Redfish API."""
        if chassis_uri[-1:] != '/':
            chassis_uri += '/'
        rqt_url = self.redfish_server_conf["base_url"]
        rqt_url += chassis_uri
        rqt_url += "Power/"
        self.log.debug("Power at " + rqt_url)
        response = requests.get(rqt_url,
                                auth=self.pod_auth,
                                verify=False)
        power_metrics = json.loads(response.text)

        return power_metrics["PowerControl"][0]["PowerConsumedWatts"]

    def run(self):
        """Thread main code."""
        self.running = True

        if not self._is_https():
            self.redfish_server_conf["base_url"] = (
                self.redfish_server_conf["base_url"].replace("https", "http")
            )

        chassis_list = self.load_chassis_list()
        # Iterate for ever, or near....
        while self.running:
            # In case of synchronized polling between several interfaces
            # wait upon condition set to perform polling
            # in case of n chassis, sync_polling_period should be adapted
            if self.sync_group != "default":
                self.condition.acquire()
                self.condition.wait()
                self.condition.release()

            for chassis in chassis_list['Members']:

                try:
                    power = self.get_power(chassis["@odata.id"])

                    # Get measurement time in nano sec.
                    data_time = int(time.time()) * 1000000000

                    self.log.debug("POWER=" + str(power))
                    data = {
                        "environment": self.environment,
                        "sender": self.server_id,
                        "power": power,
                        "data_time": data_time
                    }
                    self.log.debug(data)
                    data_poster = DataPoster(data,
                                             self.data_server_conf)
                    data_poster.start()
                except Exception:  # pylint: disable=broad-except
                    # No: default case
                    err_text = sys.exc_info()[0]
                    log_msg = "Error while trying to connect server {} in group {} ({}) \
                              for power query: {}"
                    log_msg = log_msg.format(
                        self.server_id,
                        self.sync_group,
                        self.redfish_server_conf["base_url"],
                        err_text
                    )
                    self.log.debug(traceback.format_exc())
                    self.log.error(err_text)

            # only in case of no synchronized polling between interfaces
            if self.sync_group == "default":
                time.sleep(self.redfish_server_conf["polling_interval"])
        log_msg = "Thread for server {} in group{} is teminated"
        log_msg += log_msg.format(self.server_id, self.sync_group)
        self.log.debug(log_msg)
