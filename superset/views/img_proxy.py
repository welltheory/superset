from typing import Any, Dict
import requests
from urllib.parse import urlparse
from flask import g, request, Response
from flask_appbuilder.api import expose
from superset import event_logger
from superset.utils.core import (
    get_user_id,
)
from .base import BaseSupersetView

class ImgProxyView(BaseSupersetView):
    route_base = "/img_proxy"

    @expose("/")
    @event_logger.log_this
    def img_proxy(self) -> Response:
        """
        Proxy to an external URL, to overcome CORS restrictions.
        Returns a HTTP response containing the resource fetched from the external URL.
        """
        if not get_user_id():
            raise Exception("User context not found")
        
        url = request.args.get('url')

        if not url:
            return Response("URL parameter 'url' is missing", status=400)

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ['http', 'https']:
            return Response("Invalid URL scheme", status=400)
        
        try:
            response = self.fetch_resource(url)
        except Exception:
            return Response("Error fetching resource", status=500)

        return self.build_response(response)

    def fetch_resource(self, url: str) -> Any:
        """Fetch the resource from the external server and handle errors."""
        try:
            response = requests.get(url)
            response.raise_for_status()

            return response
        except requests.RequestException as e:
            raise e

    def build_response(self, response: requests.Response) -> Response:
        """Build the HTTP response to return based on the fetched resource."""
        allowed_content_types = ['image/']
        content_type = response.headers.get('content-type', '')
        
        if not any(content_type.startswith(content_type_prefix) for content_type_prefix in allowed_content_types):
            return Response("Response is not an allowed resource type", status=400)

        headers: Dict[str, Any] = {key: value for (key, value) in response.headers.items()}
        
        return Response(response.content, response.status_code, headers)
        
        

