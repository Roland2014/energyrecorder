#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Copyright (c) 2017 Orange and others.
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

"""Unitary test for energy module."""
# pylint: disable=unused-argument
import logging
import unittest

import mock

from energy.energy import EnergyRecorder
from energy import energy

MOCK_CONF = {"environment": {"name": "MOCK_ENV"},
             "api": {"url": "mock_url",
                     "user": "mock_user",
                     "password": "mock_password"}}
MOCK_CONF_NO_CREDS = {"environment": {"name": "MOCK_ENV"},
                      "api": {"url": "mock_url",
                              "user": None,
                              "password": None}}

CASE_NAME = "UNIT_TEST_CASE"
STEP_NAME = "UNIT_TEST_STEP"

PREVIOUS_SCENARIO = "previous_scenario"
PREVIOUS_STEP = "previous_step"


class MockHttpResponse(object):  # pylint: disable=too-few-public-methods
    """Mock response for Energy recorder API."""

    def __init__(self, text, status_code):
        """Create an instance of MockHttpResponse."""
        self.text = text
        self.status_code = status_code


API_OK = MockHttpResponse(
    '{"status": "OK"}',
    200
)
API_KO = MockHttpResponse(
    '{"message": "API-KO"}',
    500
)
RECORDER_OK = MockHttpResponse(
    '{"environment": "UNIT_TEST",'
    ' "step": "string",'
    ' "scenario": "' + CASE_NAME + '"}',
    200
)
RECORDER_KO = MockHttpResponse(
    '{"message": "An unhandled API exception occurred (MOCK)"}',
    500
)


def config_loader_mock(config_key):
    """Return mocked config values."""
    if config_key == "energy_recorder.api_url":
        return "http://pod-uri:8888"
    elif config_key == "energy_recorder.api_user":
        return "user"
    elif config_key == "energy_recorder.api_password":
        return "password"
    else:
        raise Exception("Config not mocked")


def config_loader_mock_no_creds(config_key):
    """Return mocked config values."""
    if config_key == "energy_recorder.api_url":
        return "http://pod-uri:8888"
    elif config_key == "energy_recorder.api_user":
        return ""
    elif config_key == "energy_recorder.api_password":
        return ""
    else:
        raise Exception("Config not mocked:" + config_key)


class EnergyRecorderTest(unittest.TestCase):
    """Energy module unitary test suite."""

    case_name = CASE_NAME
    request_headers = {'content-type': 'application/json'}
    returned_value_to_preserve = "value"
    exception_message_to_preserve = "exception_message"

    @mock.patch('energy.energy.requests.post',
                return_value=RECORDER_OK)
    def test_start(self, post_mock=None):
        """EnergyRecorder.start method (regular case)."""
        self.test_load_config()
        self.assertTrue(EnergyRecorder.start(self.case_name))
        post_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"],
            auth=EnergyRecorder.energy_recorder_api["auth"],
            data=mock.ANY,
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.post',
                side_effect=Exception("Internal execution error (MOCK)"))
    def test_start_error(self, post_mock=None):
        """EnergyRecorder.start method (error in method)."""
        self.test_load_config()
        self.assertFalse(EnergyRecorder.start(self.case_name))
        post_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"],
            auth=EnergyRecorder.energy_recorder_api["auth"],
            data=mock.ANY,
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.post',
                return_value=RECORDER_KO)
    def test_start_api_error(self, post_mock=None):
        """EnergyRecorder.start method (API error)."""
        self.test_load_config()
        self.assertFalse(EnergyRecorder.start(self.case_name))
        post_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"],
            auth=EnergyRecorder.energy_recorder_api["auth"],
            data=mock.ANY,
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.post',
                return_value=RECORDER_OK)
    def test_set_step(self, post_mock=None):
        """EnergyRecorder.set_step method (regular case)."""
        self.test_load_config()
        self.assertTrue(EnergyRecorder.set_step(STEP_NAME))
        post_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"] + "/step",
            auth=EnergyRecorder.energy_recorder_api["auth"],
            data=mock.ANY,
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.post',
                return_value=RECORDER_KO)
    def test_set_step_api_error(self, post_mock=None):
        """EnergyRecorder.set_step method (API error)."""
        self.test_load_config()
        self.assertFalse(EnergyRecorder.set_step(STEP_NAME))
        post_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"] + "/step",
            auth=EnergyRecorder.energy_recorder_api["auth"],
            data=mock.ANY,
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.post',
                side_effect=Exception("Internal execution error (MOCK)"))
    def test_set_step_error(self, post_mock=None):
        """EnergyRecorder.set_step method (method error)."""
        self.test_load_config()
        self.assertFalse(EnergyRecorder.set_step(STEP_NAME))
        post_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"] + "/step",
            auth=EnergyRecorder.energy_recorder_api["auth"],
            data=mock.ANY,
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.delete',
                return_value=RECORDER_OK)
    def test_stop(self, delete_mock=None):
        """EnergyRecorder.stop method (regular case)."""
        self.test_load_config()
        self.assertTrue(EnergyRecorder.stop())
        delete_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"],
            auth=EnergyRecorder.energy_recorder_api["auth"],
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.delete',
                return_value=RECORDER_KO)
    def test_stop_api_error(self, delete_mock=None):
        """EnergyRecorder.stop method (API Error)."""
        self.test_load_config()
        self.assertFalse(EnergyRecorder.stop())
        delete_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"],
            auth=EnergyRecorder.energy_recorder_api["auth"],
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @mock.patch('energy.energy.requests.delete',
                side_effect=Exception("Internal execution error (MOCK)"))
    def test_stop_error(self, delete_mock=None):
        """EnergyRecorder.stop method (method error)."""
        self.test_load_config()
        self.assertFalse(EnergyRecorder.stop())
        delete_mock.assert_called_once_with(
            EnergyRecorder.energy_recorder_api["uri"],
            auth=EnergyRecorder.energy_recorder_api["auth"],
            headers=self.request_headers,
            timeout=EnergyRecorder.CONNECTION_TIMEOUT
        )

    @energy.enable_recording(CASE_NAME)
    def __decorated_method(self):
        """Call with to energy recorder decorators."""
        return self.returned_value_to_preserve

    @energy.enable_recording(CASE_NAME)
    def __decorated_method_with_ex(self):
        """Call with to energy recorder decorators."""
        raise Exception(self.exception_message_to_preserve)

    @mock.patch("energy.energy.EnergyRecorder.get_current_scenario",
                return_value=None)
    @mock.patch("energy.energy.EnergyRecorder")
    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", return_value=MOCK_CONF)
    def test_decorators(self,
                        yaml_mock=None,
                        open_mock=None,
                        recorder_mock=None,
                        cur_scenario_mock=None):
        """Test energy module decorators."""
        self.__decorated_method()
        calls = [mock.call.start(self.case_name),
                 mock.call.stop()]
        recorder_mock.assert_has_calls(calls)

    @mock.patch("energy.energy.EnergyRecorder.get_current_scenario",
                return_value={"scenario": PREVIOUS_SCENARIO,
                              "step": PREVIOUS_STEP})
    @mock.patch("energy.energy.EnergyRecorder")
    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", return_value=MOCK_CONF)
    def test_decorators_with_previous(self,
                                      yaml_mock=None,
                                      open_mock=None,
                                      recorder_mock=None,
                                      cur_scenario_mock=None):
        """Test energy module decorators."""
        self.__decorated_method()
        calls = [mock.call.start(self.case_name),
                 mock.call.submit_scenario(PREVIOUS_SCENARIO,
                                           PREVIOUS_STEP)]
        recorder_mock.assert_has_calls(calls)

    def test_decorator_preserve_return(self):
        """Test that decorator preserve method returned value."""
        self.test_load_config()
        self.assertTrue(
            self.__decorated_method() == self.returned_value_to_preserve
        )

    @mock.patch(
        "energy.energy.finish_session")
    def test_decorator_preserve_ex(self, finish_mock=None):
        """Test that decorator preserve method exceptions."""
        self.test_load_config()
        with self.assertRaises(Exception) as context:
            self.__decorated_method_with_ex()
        self.assertTrue(
            self.exception_message_to_preserve in context.exception
        )
        self.assertTrue(finish_mock.called)

    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", return_value=MOCK_CONF)
    @mock.patch("energy.energy.requests.get",
                return_value=API_OK)
    def test_load_config(self, yaml_mock=None, open_mock=None, get_mock=None):
        """Test load config."""
        EnergyRecorder.energy_recorder_api = None
        EnergyRecorder.load_config()
        self.assertEquals(
            EnergyRecorder.energy_recorder_api["auth"],
            ("mock_user", "mock_password")
        )
        self.assertEquals(
            EnergyRecorder.energy_recorder_api["uri"],
            "mock_url/recorders/environment/MOCK_ENV"
        )
        self.assertTrue(EnergyRecorder.energy_recorder_api["available"])

    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", return_value=MOCK_CONF_NO_CREDS)
    @mock.patch("energy.energy.requests.get",
                return_value=API_OK)
    def test_load_config_no_creds(self, yaml_mock=None,
                                  open_mock=None, get_mock=None):
        """Test load config without creds."""
        EnergyRecorder.energy_recorder_api = None
        EnergyRecorder.load_config()
        self.assertEquals(EnergyRecorder.energy_recorder_api["auth"], None)
        self.assertEquals(
            EnergyRecorder.energy_recorder_api["uri"],
            "mock_url/recorders/environment/MOCK_ENV"
        )
        self.assertTrue(EnergyRecorder.energy_recorder_api["available"])

    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", side_effect=Exception("load config error"))
    def test_load_config_ex(self, yaml_mock=None, open_mock=None):
        """Test load config with exception."""
        with self.assertRaises(Exception):
            EnergyRecorder.energy_recorder_api = None
            EnergyRecorder.load_config()
        self.assertEquals(EnergyRecorder.energy_recorder_api, None)

    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", return_value=MOCK_CONF)
    @mock.patch("energy.energy.requests.get",
                return_value=API_KO)
    def test_load_config_api_ko(self, loader_mock=None, pod_mock=None,
                                get_mock=None):
        """Test load config with API unavailable."""
        EnergyRecorder.energy_recorder_api = None
        EnergyRecorder.load_config()
        self.assertFalse(EnergyRecorder.energy_recorder_api["available"])

    @mock.patch("__builtin__.open", spec=open)
    @mock.patch("yaml.load", return_value=MOCK_CONF)
    @mock.patch('energy.energy.requests.get',
                return_value=RECORDER_OK)
    def test_get_current_scenario(self, get_mock=None,
                                  yaml_mock=None, open_mock=None):
        """Test get_current_scenario."""
        self.test_load_config()
        scenario = EnergyRecorder.get_current_scenario()
        self.assertTrue(scenario is not None)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    # logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger("urllib3.connectionpool").setLevel(level=logging.INFO)

    unittest.main(verbosity=2)
