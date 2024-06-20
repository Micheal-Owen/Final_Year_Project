from django.shortcuts import render, redirect
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Packet, NetworkActivity
from .serializers import PacketSerializer
from django.core.paginator import Paginator
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count
from django.template.loader import render_to_string
from django.http import HttpResponse
from xhtml2pdf import pisa
import io
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
import base64
import matplotlib.pyplot as plt

def cover(request):
    """
    Render the cover page.

    This function is responsible for rendering the cover page. It takes a request
    object as a parameter and returns a rendered HTML response.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered cover page.
    """
    # Render the cover.html template and return the response
    return render(request, 'cover.html')



def login_view(request):
    """
    Handles the login view.

    This function is called when the user submits the login form. It checks if the
    username and password are correct and if so, it logs the user in and redirects
    to the dashboard. If the username and password are incorrect, it displays an
    error message.

    Parameters:
    request (HttpRequest): The HTTP request object.

    Returns:
    HttpResponse: The HTTP response object.
    """
    # Check if the request method is POST
    if request.method == 'POST':
        # Get the username and password from the request data
        username = request.POST['username']
        password = request.POST['password']

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        # If the user is authenticated, log them in and redirect to the dashboard
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            # Display an error message if the username and password are incorrect
            messages.error(request, 'Invalid username or password.')

    # Render the login page
    return render(request, 'login.html')

@csrf_exempt
def register_view(request):
    """
    Registers a new user.

    This function is called when the user submits the registration form.
    It checks if the username already exists and if the passwords match.
    If everything is correct, it creates a new user and redirects to the login page.

    Parameters:
    request (HttpRequest): The HTTP request object.

    Returns:
    HttpResponse: The HTTP response object.
    """
    # Check if the request method is POST
    if request.method == 'POST':
        # Get the username and passwords from the request
        username = request.POST['username']
        password = request.POST['password']
        password_confirm = request.POST['password_confirm']

        # Check if the passwords match
        if password == password_confirm:
            # Check if the username already exists
            if User.objects.filter(username=username).exists():
                # If the username already exists, show an error message
                messages.error(request, 'Username already exists.')
            else:
                # If the username is available, create a new user
                user = User.objects.create_user(username=username, password=password)
                user.save()

                # Show a success message and redirect to the login page
                messages.success(request, 'Account created successfully.')
                return redirect('login')
        else:
            # If the passwords do not match, show an error message
            messages.error(request, 'Passwords do not match.')

    # If the request method is not POST, render the registration form
    return render(request, 'register.html')



def logout_view(request):
    """
    Logs out the user and redirects to the login page.

    This function is called when the user clicks the logout button.
    It uses the Django logout function to end the user's session
    and then redirects the user to the login page.

    Parameters:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponseRedirect: A redirect to the login page.
    """
    # End the user's session
    logout(request)

    # Redirect the user to the login page
    return redirect('login')




@login_required
def dashboard(request):
    """
    Renders the dashboard page.

    This function is decorated with the @login_required decorator, which means
    that the user must be authenticated to access the page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The HTTP response object containing the rendered dashboard page.
    """
    # Get all packets from the database ordered by timestamp in descending order
    packets = Packet.objects.all().order_by('-timestamp')

    # Create a paginator to display 10 packets per page
    paginator = Paginator(packets, 10)

    # Get the page number from the request
    page_number = request.GET.get('page')

    # Get the page of packets for the current page number
    page_obj = paginator.get_page(page_number)

    # Create a context dictionary with the page of packets
    context = {
        'page_obj': page_obj,
    }

    # Render the dashboard.html template with the context
    return render(request, 'dashboard.html', context)



@login_required
def analytics(request):
    """
    Renders the analytics page.

    This function is decorated with the @login_required decorator, which means
    that the user must be authenticated to access the page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The HTTP response object containing the rendered analytics page.
    """
    # Get all packets from the database
    packets = Packet.objects.all()

    # Create a context dictionary with the packets
    context = {
        'packets': packets,
    }

    # Render the analytics.html template with the context
    return render(request, 'analytics.html', context)



@login_required
def packet_capture(request):
    """
    Renders the packet capture page.

    This function is decorated with the @login_required decorator, which means
    that the user must be authenticated to access the page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The HTTP response containing the rendered packet capture page.
    """
    # Retrieve all packets from the Packet model ordered by timestamp in descending order
    packets = Packet.objects.all().order_by('-timestamp')

    # Create a paginator object with 10 packets per page
    paginator = Paginator(packets, 10)

    # Get the page number from the request parameters
    page_number = request.GET.get('page')

    # Retrieve the page of packets based on the page number
    page_obj = paginator.get_page(page_number)

    # Create the context dictionary with the page object
    context = {
        'page_obj': page_obj,
    }

    # Render the packet capture page with the context
    return render(request, 'packet_capture.html', context)

# Display Mitigation Page
@login_required
def mitigation(request):
    """
    Renders the mitigation page.

    This function is decorated with the @login_required decorator, which means
    that the user must be authenticated to access the page.

    Returns:
        HttpResponse: The rendered mitigation.html page.
    """
    # Render the mitigation.html page
    return render(request, 'mitigation.html')


# Display the current status of the network, changes the status incase an attack occurs
@login_required
def current_attack_status(request):
    """
    Returns a JSON response indicating the current attack status.

    The response includes a flag indicating whether an attack is currently
    underway and, if so, details of the most recent attack.

    Returns:
        JsonResponse: A JSON response containing the current attack status.
    """
    # Get the current time and one minute ago
    now = timezone.now()
    one_minute_ago = now - timedelta(minutes=1)

    # Find any recent attacks
    recent_attacks = Packet.objects.filter(
        is_attack=True, timestamp__gte=one_minute_ago
    )

    # If there are recent attacks, return details of the most recent one
    if recent_attacks.exists():
        attack = recent_attacks.latest('timestamp')
        report = (
            f"Attack detected:\n"
            f"Type: {attack.attack_type}\n"
            f"Source IP: {attack.src_ip}\n"
            f"Destination IP: {attack.dst_ip}\n"
            f"Destination Port: {attack.dst_port}\n"
            f"Protocol: {attack.protocol}\n"
            f"Time: {attack.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return JsonResponse({'is_under_attack': True, 'report': report})

    # Otherwise, return a flag indicating that no attacks are underway
    return JsonResponse({'is_under_attack': False})

## Displays the historical attacks and what they targetted, also including some mitigaton techniques
@login_required
def historical_data(request):
    """
    Returns a JSON response containing historical attack data.

    The response includes the attack type, count, distinct source IPs,
    distinct destination IPs, and distinct protocols for each attack type.

    Returns:
        JsonResponse: A JSON response containing historical attack data.
    """
    # Query the Packet model to get the attack types and their corresponding counts
    historical_attacks = Packet.objects.filter(is_attack=True).values('attack_type').annotate(
        count=Count('id'),
        details=Count('id'),
        src_ips=Count('src_ip', distinct=True),
        dst_ips=Count('dst_ip', distinct=True),
        protocols=Count('protocol', distinct=True)
    )

    # Create a dictionary containing the attack data
    data = {
        'attacks': [
            {
                # Index of the attack in the list
                'id': index,
                # Name of the attack type
                'name': attack['attack_type'],
                # Count of the attack type
                'count': attack['count'],
                # List of distinct source IPs
                'src_ips': list(Packet.objects.filter(attack_type=attack['attack_type']).values_list('src_ip', flat=True).distinct()),
                # List of distinct destination IPs
                'dst_ips': list(Packet.objects.filter(attack_type=attack['attack_type']).values_list('dst_ip', flat=True).distinct()),
                # List of distinct protocols
                'protocols': list(Packet.objects.filter(attack_type=attack['attack_type']).values_list('protocol', flat=True).distinct()),
                # List of mitigation techniques for the attack type
                'mitigation_techniques': get_mitigation_techniques(attack['attack_type'])
            } for index, attack in enumerate(historical_attacks)
        ]
    }
    return JsonResponse(data)

@login_required
def get_mitigation_techniques(attack_type):
    """
    Returns a list of mitigation techniques for a given attack type.
    
    If the attack type is not found in the techniques dictionary, a default list of general mitigation techniques is returned.
    
    Args:
        attack_type (str): The type of attack.
        
    Returns:
        list: A list of mitigation techniques.
    """
    # Dictionary mapping attack types to a list of mitigation techniques
    techniques = {
        'DDOS attack-HOIC': ['Rate limiting', 'IP blocking', 'Traffic analysis'],
        'DDOS attack-LOIC-UDP': ['Firewalls', 'Traffic filtering', 'Rate limiting'],
        'FTP-BruteForce': ['Account lockout policies', 'Strong passwords', 'Two-factor authentication'],
        'Brute Force -Web': ['CAPTCHA', 'Account lockout policies', 'IP blacklisting'],
        'Brute Force -XSS': ['Input validation', 'Output encoding', 'Web application firewall'],
        'SQL Injection': ['Prepared statements', 'Stored procedures', 'Input validation']
    }
    # Return the list of mitigation techniques for the given attack type, or the default list if not found
    return techniques.get(attack_type, ['General mitigation technique 1', 'General mitigation technique 2'])

@login_required
def ip_addresses_data(request):
    """
    View function that returns a JSON response containing a list of IP addresses and their associated attacks.

    The response includes the IP address, the number of attacks associated with the IP address, and a list of attacks.
    Each attack includes the type of attack, the destination IP address, and the time the attack occurred.

    Returns:
        JsonResponse: A JSON response containing the IP addresses and associated attacks.
    """
    # Query the Packet model to get the source IP addresses and their corresponding counts
    ip_addresses = Packet.objects.values('src_ip').annotate(count=Count('id')).order_by('-count')

    # Create a dictionary containing the IP addresses and associated attacks
    data = {
        'ip_addresses': [
            {
                'id': index,  # Index of the IP address in the list
                'address': ip['src_ip'],  # Source IP address
                'attacks': [  # List of attacks associated with the IP address
                    {
                        'type': packet.attack_type,  # Type of attack
                        'dst_ip': packet.dst_ip,  # Destination IP address
                        'time': packet.timestamp.strftime('%Y-%m-%d %H:%M:%S')  # Time the attack occurred
                    } for packet in Packet.objects.filter(src_ip=ip['src_ip'])  # Query the Packet model to get the attacks
                ]
            } for index, ip in enumerate(ip_addresses)  # Iterate over the IP addresses and their counts
        ]
    }

    # Return the JSON response
    return JsonResponse(data)


@login_required
@api_view(['POST'])
def packet_data(request):
    """
    Endpoint for saving packet data to the database.
    """
    if request.method == 'POST':
        # Deserialize the request data into a Packet object
        serializer = PacketSerializer(data=request.data)
        if serializer.is_valid():
            packet = serializer.save()
            # Check if the packet is an attack
            is_attack = request.data.get('is_attack')
            attack_type = request.data.get('attack_type')
            if is_attack:
                # Create a report for the detected attack
                report = f"Attack detected:\nType: {attack_type}\nSource IP: {packet.src_ip}\nDestination IP: {packet.dst_ip}\nDestination Port: {packet.dst_port}\nProtocol: {packet.protocol}\nLength: {packet.length}"
                # Create a NetworkActivity object with the attack details
                NetworkActivity.objects.create(
                    activity_type=attack_type,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    report=report
                )
            # Return a success response
            return Response({'status': 'success'})
        # Return an error response if the serializer is not valid
        return Response(serializer.errors, status=400)

@login_required
def network_activity_data(request):
    """
    Endpoint for fetching network activity data.
    
    Returns a JSON response containing the counts of normal activity, abnormal activity,
    mitigated attacks, and pending requests.
    """
    # Get the counts of normal activity, abnormal activity, mitigated attacks, and pending requests
    normal_activity_count = Packet.objects.filter(is_attack=False).count()
    abnormal_activity_count = Packet.objects.filter(is_attack=True).count()
    mitigated_attacks_count = NetworkActivity.objects.filter(activity_type__icontains='Mitigated').count()
    pending_requests_count = NetworkActivity.objects.filter(activity_type__icontains='Pending').count()

    # Create a dictionary containing the counts
    data = {
        'normalActivityCount': normal_activity_count,  # Count of normal activity
        'abnormalActivityCount': abnormal_activity_count,  # Count of abnormal activity
        'mitigatedAttacksCount': mitigated_attacks_count,  # Count of mitigated attacks
        'pendingRequestsCount': pending_requests_count,  # Count of pending requests
    }
    
    # Return the JSON response
    return JsonResponse(data)

@login_required
def traffic_overview_data(request):
    """
    Endpoint for fetching traffic overview data.
    
    Returns a JSON response containing the timestamps and lengths of all Packet objects.
    """
    # Get all Packet objects
    packets = Packet.objects.all()
    
    # Extract timestamps and lengths from Packet objects
    times = [packet.timestamp.strftime('%H:%M') for packet in packets]
    lengths = [packet.length for packet in packets]
    
    # Create a dictionary containing the timestamps and lengths
    data = {
        'times': times,  # List of timestamps in 'HH:MM' format
        'lengths': lengths  # List of lengths in bytes
    }
    
    # Return the JSON response
    return JsonResponse(data)

@login_required
def attack_types_data(request):
    """
    Endpoint for fetching attack types data.
    
    Returns a JSON response containing the counts of each attack type in Packet objects.
    """
    # Get the distinct attack types along with their counts
    attack_types = Packet.objects.values('attack_type').annotate(count=Count('id'))
    
    # Filter out the None values and create a dictionary with attack types as keys and counts as values
    data = {item['attack_type']: item['count'] for item in attack_types if item['attack_type']}
    
    # Return the JSON response
    return JsonResponse(data)


@login_required
@csrf_exempt
def packet(request):
    """
    Endpoint for handling incoming packet data.

    This endpoint expects a POST request with a JSON payload containing packet data.
    The payload should have the following keys:
    - src_ip: source IP address
    - dst_ip: destination IP address
    - dst_port: destination port
    - protocol: protocol of the packet
    - length: length of the packet
    - is_attack: boolean indicating if the packet is an attack
    - attack_type: type of the attack

    If the packet is an attack, a NetworkActivity object is created with the attack details.

    Returns a JSON response with a success message.
    """
    # Check if the request is a POST request
    if request.method == 'POST':
        # Parse the JSON payload
        data = json.loads(request.body)

        # Create a Packet object with the packet data
        packet = Packet(
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
            dst_port=data['dst_port'],
            protocol=data['protocol'],
            length=data['length'],
            is_attack=data['is_attack'],
            attack_type=data['attack_type']
        )
        packet.save()

        # If the packet is an attack, create a NetworkActivity object
        if data['is_attack']:
            report = f"Attack detected:\nType: {data['attack_type']}\nSource IP: {data['src_ip']}\nDestination IP: {data['dst_ip']}\nDestination Port: {data['dst_port']}\nProtocol: {data['protocol']}\nLength: {data['length']}"
            NetworkActivity.objects.create(
                activity_type=data['attack_type'],
                src_ip=data['src_ip'],
                dst_ip=data['dst_ip'],
                dst_port=data['dst_port'],
                report=report
            )

        # Return a success response
        return JsonResponse({'status': 'success', 'message': 'Packet saved successfully'})


@login_required
def generate_report(request):
    """
    Generate a PDF report containing statistics and charts about network activity.

    Returns a PDF file as an HttpResponse.
    """
    # Get all packets and count them
    packets = Packet.objects.all().order_by('-timestamp')
    total_packets = packets.count()
    total_attacks = packets.filter(is_attack=True).count()

    # Generate Most Attacked IP Addresses Chart
    ip_counts = packets.values('dst_ip').annotate(count=Count('dst_ip')).order_by('-count')
    ips = [entry['dst_ip'] for entry in ip_counts]  # Get the IP addresses
    ip_values = [entry['count'] for entry in ip_counts]  # Get the count of each IP address

    # Generate the chart
    fig, ax = plt.subplots()  # Create a figure and axes
    ax.pie(ip_values, labels=ips, autopct='%1.1f%%')  # Plot the pie chart
    ax.set_title('IP Addresses Attacked Distribution')  # Set the title
    ip_buffer = io.BytesIO()  # Create a buffer to store the chart image
    plt.savefig(ip_buffer, format='png')  # Save the chart image to the buffer
    ip_buffer.seek(0)  # Set the buffer position to the beginning
    ip_chart = base64.b64encode(ip_buffer.read()).decode('utf-8')  # Encode the chart image as base64
    plt.close(fig)  # Close the figure and axes

    # Generate Most Attacked Ports Chart
    port_counts = packets.values('dst_port').annotate(count=Count('dst_port')).order_by('-count')
    ports = [entry['dst_port'] for entry in port_counts]
    port_values = [entry['count'] for entry in port_counts]

    # Generate the chart
    fig, ax = plt.subplots()
    ax.pie(port_values, labels=ports, autopct='%1.1f%%')
    ax.set_title('Ports Attacked Distribution')
    port_buffer = io.BytesIO()
    plt.savefig(port_buffer, format='png')
    port_buffer.seek(0)
    port_chart = base64.b64encode(port_buffer.read()).decode('utf-8')
    plt.close(fig)

    # Generate Protocol Distribution Chart
    protocol_counts = packets.values('protocol').annotate(count=Count('protocol')).order_by('-count')
    protocols = [entry['protocol'] for entry in protocol_counts]
    protocol_values = [entry['count'] for entry in protocol_counts]

    # Generate the chart
    fig, ax = plt.subplots()
    ax.pie(protocol_values, labels=protocols, autopct='%1.1f%%')
    ax.set_title('Protocols used Distribution')
    protocol_buffer = io.BytesIO()
    plt.savefig(protocol_buffer, format='png')
    protocol_buffer.seek(0)
    protocol_chart = base64.b64encode(protocol_buffer.read()).decode('utf-8')
    plt.close(fig)

    # Prepare the context for rendering the report template
    context = {
        'total_packets': total_packets,
        'total_attacks': total_attacks,
        'ip_chart': ip_chart,
        'port_chart': port_chart,
        'protocol_chart': protocol_chart,
    }

    # Render the report template to HTML
    html = render_to_string('report_template.html', context)

    # Create an HttpResponse to send the PDF file
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="network_activity_report.pdf"'

    # Generate the PDF file
    pisa_status = pisa.CreatePDF(
        io.BytesIO(html.encode('utf-8')), dest=response
    )

    # Return the PDF file if no errors occurred, otherwise return an error message
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    return response


@login_required
def real_time_network_traffic_data(request):
    """
    This function retrieves network traffic data within a specified time range
    and returns it as JSON response.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: The HTTP response containing the network traffic data.
    """
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    try:
        # If start and end dates are provided, filter packets within the range
        if start_date and end_date:
            packets = Packet.objects.filter(timestamp__range=[start_date, end_date])
        # Otherwise, retrieve all packets
        else:
            packets = Packet.objects.all()

        # Extract the timestamps and packet lengths
        times = [packet.timestamp.strftime('%H:%M:%S') for packet in packets]
        lengths = [packet.length for packet in packets]

        # Create a dictionary with the extracted data
        data = {
            'times': times,
            'lengths': lengths
        }

        # Return the data as JSON response
        return JsonResponse(data)

    # If an exception occurs, print the error and return a JSON response with the error message
    except Exception as e:
        print(f"Error: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def top_talkers_data(request):
    """
    Retrieves the top talkers based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: The HTTP response containing the top talkers data.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # If start and end dates are provided, filter packets within the range
    if start_date and end_date:
        top_talkers = Packet.objects.filter(timestamp__range=[start_date, end_date]).values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10]
    # Otherwise, retrieve the top talkers for all packets
    else:
        top_talkers = Packet.objects.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10]
        
    # Extract the source IP addresses and their corresponding counts
    src_ips = [entry['src_ip'] for entry in top_talkers]
    counts = [entry['count'] for entry in top_talkers]

    # Create a dictionary with the extracted data
    data = {
        'src_ips': src_ips,
        'counts': counts
    }

    # Return the data as JSON response
    return JsonResponse(data)

@login_required
def top_listeners_data(request):
    """
    Retrieves the top listeners based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the top listeners and their counts.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Filter the Packet objects based on the date range and retrieve the top listeners
    if start_date and end_date:
        # Filter packets within the date range and retrieve the top listeners
        top_listeners = Packet.objects.filter(timestamp__range=[start_date, end_date]).values('dst_ip').annotate(count=Count('dst_ip')).order_by('-count')[:10]
    else:
        # Retrieve the top listeners for all packets
        top_listeners = Packet.objects.values('dst_ip').annotate(count=Count('dst_ip')).order_by('-count')[:10]
        
    # Extract the IP addresses and counts from the top listeners
    dst_ips = [entry['dst_ip'] for entry in top_listeners]
    counts = [entry['count'] for entry in top_listeners]

    # Create the data dictionary and return the JSON response
    data = {
        'dst_ips': dst_ips,  # List of IP addresses of the top listeners
        'counts': counts  # List of counts corresponding to each IP address
    }
    return JsonResponse(data)

@login_required
def attack_trends_data(request):
    """
    Get the attack trends based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: The JSON response containing the times and attack trends.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Retrieve the attack types and their counts based on the date range
    if start_date and end_date:
        attack_types = Packet.objects.filter(timestamp__range=[start_date, end_date]).values('attack_type').annotate(count=Count('id')).order_by('attack_type')
    else:
        attack_types = Packet.objects.values('attack_type').annotate(count=Count('id')).order_by('attack_type')

    # Get the times for the last 60 packets
    times = [packet.timestamp.strftime('%H:%M:%S') for packet in Packet.objects.all().order_by('timestamp')[:60]]

    # Create the attack trends data
    attack_trends = []
    for attack in attack_types:
        # Get the packet lengths for the last 60 packets of the current attack type
        trend = {
            'label': attack['attack_type'],  # Label for the attack type
            'data': [packet.length for packet in Packet.objects.filter(attack_type=attack['attack_type'])[:60]],  # Packet lengths for the last 60 packets of the attack type
        }
        attack_trends.append(trend)

    # Create the response data
    data = {
        'times': times,  # Times for the last 60 packets
        'attack_trends': attack_trends,  # Attack trends data
    }
    
    # Return the JSON response
    return JsonResponse(data)

@login_required
def protocol_usage_data(request):
    """
    Get the usage of different protocols based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the names, usage counts, colors, and hover colors of the protocols.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # Query the Packet model to get the usage of different protocols
    if start_date and end_date:
        protocol_usage = Packet.objects.filter(timestamp__range=[start_date, end_date]).values('protocol').annotate(count=Count('protocol')).order_by('-count')
    else:
        protocol_usage = Packet.objects.values('protocol').annotate(count=Count('protocol')).order_by('-count')

    # Extract the protocol names and usage counts from the query result
    protocol_names = [entry['protocol'] for entry in protocol_usage]
    protocol_counts = [entry['count'] for entry in protocol_usage]

    # Define the colors for each protocol
    colors = ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b', '#858796', '#f8f9fc']

    # Create a dictionary with the required data
    data = {
        'protocols': protocol_names,
        'usage': protocol_counts,
        'colors': colors,
        'hoverColors': colors
    }

    # Return the data as a JSON response
    return JsonResponse(data)

@login_required
def attack_severity_data(request):
    """
    Get the severity of attacks based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the times and severity of attacks.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Filter the Packet objects based on the date range and retrieve the attack severity
    if start_date and end_date:
        attack_severity = Packet.objects.filter(timestamp__range=[start_date, end_date]).values('timestamp').annotate(severity=Count('id')).order_by('timestamp')[:60]
    else:
        attack_severity = Packet.objects.values('timestamp').annotate(severity=Count('id')).order_by('timestamp')[:60]

    # Extract the times and severity from the attack_severity
    times = [entry['timestamp'].strftime('%H:%M:%S') for entry in attack_severity]
    severity = [entry['severity'] for entry in attack_severity]

    # Create the data dictionary and return the JSON response
    data = {
        'times': times,
        'severity': severity
    }
    return JsonResponse(data)

@login_required
def response_time_data(request):
    """
    Get the response times for mitigated incidents based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the response times and incidents.
    """

    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # Filter the NetworkActivity objects based on the date range and the activity type
    if start_date and end_date:
        responses = NetworkActivity.objects.filter(activity_type__icontains='Mitigated',
                                                    timestamp__range=[start_date, end_date]).values('timestamp')
    else:
        responses = NetworkActivity.objects.filter(activity_type__icontains='Mitigated').values('timestamp')

    # Extract the response times and incidents
    response_times = [response['timestamp'].strftime('%H:%M:%S') for response in responses]
    incidents = ['Incident {}'.format(i+1) for i in range(len(response_times))]

    # Create the data dictionary and return the JSON response
    data = {
        'incidents': incidents,
        'response_times': response_times
    }
    return JsonResponse(data)

@login_required
def most_used_ports_data(request):
    """
    Retrieve the most used ports and their counts based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the most used ports and their counts.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Filter the Packet objects based on the date range and retrieve the most used ports
    if start_date and end_date:
        ports_data = Packet.objects.filter(timestamp__range=[start_date, end_date]).values('dst_port').annotate(count=Count('dst_port')).order_by('-count')[:10]
    else:
        ports_data = Packet.objects.values('dst_port').annotate(count=Count('dst_port')).order_by('-count')[:10]

    # Extract the ports and counts from the ports_data
    ports = [entry['dst_port'] for entry in ports_data]
    counts = [entry['count'] for entry in ports_data]

    # Create the data dictionary and return the JSON response
    data = {
        'ports': ports,
        'counts': counts
    }
    return JsonResponse(data)


@login_required
def correlation_matrix_data(request):
    """
    Retrieve the correlation matrix data for attack types based on the given date range.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: The JSON response containing the attack types and correlation matrix data.
    """
    # Get the start and end dates from the request parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Retrieve the attack types based on the date range
    if start_date and end_date:
        attack_types = list(Packet.objects.filter(timestamp__range=[start_date, end_date]).values_list('attack_type', flat=True).distinct())
    else:
        attack_types = list(Packet.objects.values_list('attack_type', flat=True).distinct())
    
    # Filter out None values from the attack types
    attack_type_names = [attack for attack in attack_types if attack is not None]
    
    # Initialize the correlation matrix data with zeros
    correlation_data = [[0]*len(attack_type_names) for _ in range(len(attack_type_names))]
    
    # Calculate the correlation between each attack type pair
    for i, attack1 in enumerate(attack_type_names):
        for j, attack2 in enumerate(attack_type_names):
            if i <= j:
                # Count the number of packets with the same attack type
                correlation = Packet.objects.filter(attack_type=attack1).filter(attack_type=attack2).count()
                correlation_data[i][j] = correlation
                correlation_data[j][i] = correlation
                
    # Create the response data
    data = {
        'attack_types': attack_type_names,  # List of attack types
        'correlation': correlation_data  # Correlation matrix data
    }
    
    # Return the JSON response
    return JsonResponse(data)

