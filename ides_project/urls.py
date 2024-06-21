"""
URL configuration for ides_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from ids_app import views

urlpatterns = [
    # Admin route
    path('admin/', admin.site.urls),
    
    # Home page route
    path('', views.cover, name='cover'),
    
    # Authentication routes
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    
    # Dashboard route
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Analysis routes
    path('analytics/', views.analytics, name='analytics'),
    path('real-time-network-traffic-data/', views.real_time_network_traffic_data, name='real_time_network_traffic_data'),
    path('top-talkers-data/', views.top_talkers_data, name='top_talkers_data'),
    path('top-listeners-data/', views.top_listeners_data, name='top_listeners_data'),
    path('attack-trends-data/', views.attack_trends_data, name='attack_trends_data'),
    path('protocol-usage-data/', views.protocol_usage_data, name='protocol_usage_data'),
    path('attack-severity-data/', views.attack_severity_data, name='attack_severity_data'),
    path('response-time-data/', views.response_time_data, name='response_time_data'),
    path('correlation-matrix-data/', views.correlation_matrix_data, name='correlation_matrix_data'),
    path('most-used-ports-data/', views.most_used_ports_data, name='most_used_ports_data'),
    
    # Packet capture route
    path('pkt_capture/', views.packet_capture, name='packet_capture'),
    
    # Mitigation routes
    path('mitigation/', views.mitigation, name='mitigation'),
    path('api/current-attack-status/', views.current_attack_status, name='current_attack_status'),
    path('api/historical-data/', views.historical_data, name='historical_data'),
    path('api/ip-addresses-data/', views.ip_addresses_data, name='ip_addresses_data'),
    
    # Report generation route
    path('generate_report/', views.generate_report, name='generate_report'),
    
    # API routes for packet and network data
    path('api/packet/', views.packet_data, name='packet_data'),
    path('network-activity-data/', views.network_activity_data, name='network_activity_data'),
    path('traffic-overview-data/', views.traffic_overview_data, name='traffic_overview_data'),
    path('attack-types-data/', views.attack_types_data, name='attack_types_data'),
]
