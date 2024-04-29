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
from io import BytesIO
from typing import Any
from urllib.parse import urlparse

import requests
from flask import abort, request, Response
from flask_appbuilder.api import expose
from flask_wtf.csrf import same_origin
from PIL import Image

from superset import event_logger
from superset.superset_typing import FlaskResponse
from superset.utils.core import get_user_id

from .base import BaseSupersetView


class ImgProxyView(BaseSupersetView):
    route_base = "/img_proxy"

    @expose("/")
    @event_logger.log_this
    def img_proxy(self) -> FlaskResponse:
        """
        Proxy to an external URL, to overcome CORS restrictions.
        Returns a HTTP response containing the resource fetched from the external URL.
        """
        if not get_user_id():
            abort(403)

        url = request.args.get("url")
        allowed_content_types = ["image/"]

        if not url:
            abort(400)

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            abort(400)

        if not request.referrer or (
            request.referrer and not same_origin(request.referrer, request.url_root)
        ):
            abort(403)

        try:
            response = self.fetch_resource(url)
        except Exception:
            abort(500)

        content_type = response.headers.get("content-type", "")

        if not any(
            content_type.startswith(content_type_prefix)
            for content_type_prefix in allowed_content_types
        ):
            abort(400)

        try:
            is_valid_image = self.validate_image(response.content)
            if not is_valid_image:
                abort(400)
        except Exception:
            abort(500)

        headers: dict[str, Any] = {
            key: value for (key, value) in response.headers.items()
        }

        return Response(response.content, response.status_code, headers)

    def validate_image(self, image_content) -> bool:
        """
        Load the image from bytes, Pillow will raise an IOError if the file is not an image
        """
        try:
            with Image.open(BytesIO(image_content)) as img:
                if img.format:
                    return True
            return False
        except OSError as e:
            raise e
        except Exception as e:
            raise e

    def fetch_resource(self, url: str) -> requests.Response:
        """Fetch the resource from the external server and handle errors."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            raise e
