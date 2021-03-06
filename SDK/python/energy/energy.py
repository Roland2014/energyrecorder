#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Copyright (c) 2017 Orange and others.
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

"""This module manages calls to Energy recording API."""

import json
import logging
import urllib

from functools import wraps
import requests
import urllib3
import yaml


def finish_session(current_scenario):
    """Finish a recording session."""
    if current_scenario is None:
        EnergyRecorder.stop()
    else:
        EnergyRecorder.submit_scenario(
            current_scenario["scenario"],
            current_scenario["step"]
        )


def enable_recording(scenario):
    """Receive decorator parameter."""
    def method_decorator(method):
        """
        Record energy during method execution.

        Decorator to record energy during "method" exection.

            param method: Method to suround with start and stop
            :type method: function

            .. note:: "method" should belong to a class having a "case_name"
                      attribute
        """
        @wraps(method)
        def wrapper(*args):
            """
            Record energy during method execution (implementation).

            Wrapper for decorator to handle method arguments.
            """
            current_scenario = EnergyRecorder.get_current_scenario()
            EnergyRecorder.start(scenario)
            try:
                return_value = method(*args)
                finish_session(current_scenario)
            except Exception:  # pylint: disable=broad-except
                finish_session(current_scenario)
                raise
            return return_value
        return wrapper
    return method_decorator


# Class to manage energy recording sessions
class EnergyRecorder(object):
    """Manage Energy recording session."""

    logger = logging.getLogger(__name__)
    # Energy recording API connectivity settings
    # see load_config method
    energy_recorder_api = None

    # Default initial step
    INITIAL_STEP = "running"

    # Connection timout to connect recording API
    CONNECTION_TIMEOUT = urllib3.Timeout(connect=1, read=3)

    @staticmethod
    def load_config():
        """
        Load connectivity settings from yaml.

        Load connectivity settings to Energy recording API
        Use functest global config yaml file
        """
        # Singleton pattern for energy_recorder_api static member
        # Load only if not previouly done
        if EnergyRecorder.energy_recorder_api is None:
            try:
                with open("energy/conf/energy-settings.yaml", 'r') as stream:
                    config = yaml.load(stream)
                environment = config["environment"]["name"]

                # API URL
                energy_recorder_uri = config["api"]["url"]
                assert energy_recorder_uri
                assert environment

                energy_recorder_uri += "/recorders/environment/"
                energy_recorder_uri += urllib.quote_plus(environment)
                EnergyRecorder.logger.debug(
                    "API recorder at: " + energy_recorder_uri)

                # Creds
                user = config["api"]["user"]
                password = config["api"]["password"]

                if user == "" or password == "" or \
                   user is None or password is None:
                    energy_recorder_api_auth = None
                else:
                    energy_recorder_api_auth = (user, password)
                try:
                    resp = requests.get(
                        energy_recorder_uri + "/monitoring/ping",
                        auth=energy_recorder_api_auth,
                        headers={
                            'content-type': 'application/json'
                        },
                        timeout=EnergyRecorder.CONNECTION_TIMEOUT)
                    api_available = json.loads(resp.text)["status"] == "OK"
                except Exception:  # pylint: disable=broad-except
                    EnergyRecorder.logger.error(
                        "Energy recorder API is not available")
                    api_available = False

                # Final config
                EnergyRecorder.energy_recorder_api = {
                    "uri": energy_recorder_uri,
                    "auth": energy_recorder_api_auth,
                    "available": api_available
                }
            except Exception:  # pylint: disable=broad-except
                EnergyRecorder.logger.exception(
                    "Error while loading config")
                raise
        return EnergyRecorder.energy_recorder_api["available"]

    @staticmethod
    def submit_scenario(scenario, step):
        """
        Submit a complet scenario definition to Energy recorder API.

            param scenario: Scenario name
            :type scenario: string
            param step: Step name
            :type step: string
        """
        try:
            # Ensure that connectyvity settings are loaded
            if EnergyRecorder.load_config():
                return_status = True
                EnergyRecorder.logger.debug("Submitting scenario")

                # Create API payload
                payload = {
                    "step": step,
                    "scenario": scenario
                }
                # Call API to start energy recording
                response = requests.post(
                    EnergyRecorder.energy_recorder_api["uri"],
                    data=json.dumps(payload),
                    auth=EnergyRecorder.energy_recorder_api["auth"],
                    headers={
                        'content-type': 'application/json'
                    },
                    timeout=EnergyRecorder.CONNECTION_TIMEOUT
                )
                if response.status_code != 200:
                    EnergyRecorder.logger.info(
                        "Error while submitting scenario\n%s",
                        response.text)
                    return_status = False
        except Exception:  # pylint: disable=broad-except
            # Default exception handler to ensure that method
            # is safe for caller
            EnergyRecorder.logger.exception(
                "Error while submitting scenarion to energy recorder API"
            )
            return_status = False
        return return_status

    @staticmethod
    def start(scenario):
        """
        Start a recording session for scenario.

            param scenario: Starting scenario
            :type scenario: string
        """
        return_status = True
        try:
            if EnergyRecorder.load_config():
                EnergyRecorder.logger.debug("Starting recording")
                return_status = EnergyRecorder.submit_scenario(
                    scenario,
                    EnergyRecorder.INITIAL_STEP
                )
            else:
                EnergyRecorder.logger.debug("Load config fails")

        except Exception:  # pylint: disable=broad-except
            # Default exception handler to ensure that method
            # is safe for caller
            EnergyRecorder.logger.exception(
                "Error while starting energy recorder API"
            )
            return_status = False
        return return_status

    @staticmethod
    def stop():
        """Stop current recording session."""
        EnergyRecorder.logger.debug("Stopping recording")
        return_status = True
        try:
            # Ensure that connectyvity settings are loaded
            if EnergyRecorder.load_config():

                # Call API to stop energy recording
                response = requests.delete(
                    EnergyRecorder.energy_recorder_api["uri"],
                    auth=EnergyRecorder.energy_recorder_api["auth"],
                    headers={
                        'content-type': 'application/json'
                    },
                    timeout=EnergyRecorder.CONNECTION_TIMEOUT
                )
                if response.status_code != 200:
                    EnergyRecorder.logger.error(
                        "Error while starting energy recording session\n%s",
                        response.text)
                    return_status = False
        except Exception:  # pylint: disable=broad-except
            # Default exception handler to ensure that method
            # is safe for caller
            EnergyRecorder.logger.exception(
                "Error while stoping energy recorder API"
            )
            return_status = False
        return return_status

    @staticmethod
    def set_step(step):
        """Notify energy recording service of current step of the testcase."""
        EnergyRecorder.logger.debug("Setting step")
        return_status = True
        try:
            # Ensure that connectyvity settings are loaded
            if EnergyRecorder.load_config():

                # Create API payload
                payload = {
                    "step": step,
                }

                # Call API to define step
                response = requests.post(
                    EnergyRecorder.energy_recorder_api["uri"] + "/step",
                    data=json.dumps(payload),
                    auth=EnergyRecorder.energy_recorder_api["auth"],
                    headers={
                        'content-type': 'application/json'
                    },
                    timeout=EnergyRecorder.CONNECTION_TIMEOUT
                )
                if response.status_code != 200:
                    EnergyRecorder.logger.error(
                        "Error while setting current step of testcase\n%s",
                        response.text)
                    return_status = False
        except Exception:  # pylint: disable=broad-except
            # Default exception handler to ensure that method
            # is safe for caller
            EnergyRecorder.logger.exception(
                "Error while setting step on energy recorder API"
            )
            return_status = False
        return return_status

    @staticmethod
    def get_current_scenario():
        """Get current running scenario (if any, None else)."""
        EnergyRecorder.logger.debug("Getting current scenario")
        return_value = None
        try:
            # Ensure that connectyvity settings are loaded
            if EnergyRecorder.load_config():

                # Call API get running scenario
                response = requests.get(
                    EnergyRecorder.energy_recorder_api["uri"],
                    auth=EnergyRecorder.energy_recorder_api["auth"]
                )
                if response.status_code == 200:
                    return_value = json.loads(response.text)
                elif response.status_code == 404:
                    EnergyRecorder.logger.info(
                        "No current running scenario at %s",
                        EnergyRecorder.energy_recorder_api["uri"])
                    return_value = None
                else:
                    EnergyRecorder.logger.error(
                        "Error while getting current scenario\n%s",
                        response.text)
                    return_value = None
        except Exception:  # pylint: disable=broad-except
            # Default exception handler to ensure that method
            # is safe for caller
            EnergyRecorder.logger.exception(
                "Error while getting current scenario from energy recorder API"
            )
            return_value = None
        return return_value
