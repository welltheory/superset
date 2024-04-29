# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

from unittest import mock

import requests

from tests.integration_tests.base_tests import SupersetTestCase
from tests.integration_tests.constants import ADMIN_USERNAME


class ImgProxyViewTest(SupersetTestCase):
    def setUp(self):
        self.login(ADMIN_USERNAME)
        self.headers = {"Referer": "http://localhost/"}

    def tearDown(self):
        super().tearDown()

    def test_img_proxy_invalid_user_context(self):
        uri = "img_proxy/?url=https://example.com"
        self.logout()
        response = self.client.get(uri)
        assert response.status_code == 403

    def test_img_proxy_missing_url(self):
        uri = "img_proxy/?url="
        response = self.client.get(uri)
        assert response.status_code == 400

    def test_img_proxy_invalid_url(self):
        uri = "img_proxy/?url=fpt://example.com"
        response = self.client.get(uri)
        assert response.status_code == 400

    def test_img_proxy_invalid_referer(self):
        uri = "img_proxy/?url=https://example.com"
        headers = {"Referer": "http://maliciousdomain.com"}
        response = self.client.get(uri, headers=headers)
        assert response.status_code == 403

    def test_img_proxy_invalid_resource(self):
        uri = "img_proxy/?url=https://test.zyz.xyz"
        response = self.client.get(uri, headers=self.headers)
        assert response.status_code == 500

    def test_img_proxy_invalid_resource_content(self):
        with mock.patch(
            "superset.views.img_proxy.ImgProxyView.fetch_resource"
        ) as mock_fetch_resource:
            mock_response = requests.Response()
            mock_response._content = b"Mocked content"
            mock_response.status_code = 200
            mock_response.headers["content-type"] = "test/test"
            mock_fetch_resource.return_value = mock_response

            uri = "img_proxy/?url=https://example.com/image.jpg"
            response = self.client.get(uri, headers=self.headers)
            assert response.status_code == 400

    def test_img_proxy_valid_resource_content(self):
        with mock.patch(
            "superset.views.img_proxy.ImgProxyView.fetch_resource"
        ) as mock_fetch_resource:
            with mock.patch(
                "superset.views.img_proxy.ImgProxyView.validate_image"
            ) as mock_validate_image:
                mock_response = requests.Response()
                mock_response._content = b"Mocked content"
                mock_response.status_code = 200
                mock_response.headers["content-type"] = "image/jpeg"
                mock_fetch_resource.return_value = mock_response
                mock_validate_image.return_value = True

                uri = "img_proxy/?url=https://example.com/image.jpg"
                response = self.client.get(uri, headers=self.headers)

                assert response.status_code == 200
