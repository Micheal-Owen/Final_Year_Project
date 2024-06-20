from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
import re

class SessionTimeoutMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """
        Middleware to handle session timeout for non-AJAX requests.

        If the request is not an AJAX request, reset the session expiry to 5 minutes.
        If the request is an AJAX request, do not reset the session expiry.
        If the session expiry is less than 5 minutes, redirect the user to the cover page.
        """
        
        # Patterns for AJAX endpoints that should not reset the session timeout
        ajax_patterns = [
            re.compile(r'^/attack-types-data/$'),
            re.compile(r'^/network-activity-data/$'),
            re.compile(r'^/traffic-overview-data/$'),
            re.compile(r'^/real_time_network_traffic_data/$'),
            re.compile(r'^/top-listeners-data/$'),
            re.compile(r'^/top-talkers-data/$'),
            re.compile(r'^/protocol-usage-data/$'),
            re.compile(r'^/response-time-data/$'),
            re.compile(r'^/attack-severity-data/$'),
            re.compile(r'^/correlation-matrix-data/$'),
            re.compile(r'^/attack-trends-data/$'),
            re.compile(r'^/most-used-ports-data/$'),
            # Add more patterns as needed
        ]
        
        # Check if the request matches any of the AJAX patterns
        if any(pattern.match(request.path) for pattern in ajax_patterns):
            # If it's an AJAX request, do not reset the session expiry
            request.session.set_expiry(request.session.get_expiry_age())
        else:
            # For non-AJAX requests, reset the session expiry
            request.session.set_expiry(300)  # 5 minutes
        
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return
        
        # Check if the session expiry is less than 5 minutes
        if request.session.get_expiry_age() < 300:  # 5 minutes
            # Redirect the user to the cover page
            return redirect('cover')
