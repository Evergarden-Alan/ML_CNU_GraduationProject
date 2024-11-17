import os
import sys
import util

def preprocess():
       util.preprocess_dns("example/ATLAS/training_logs/h1/logs/dns","mycode/dataset/h1/dns_logs.json")
       util.preprocess_webbrowser("example/ATLAS/training_logs/h1/logs/firefox.txt","mycode/dataset/h1/webbrowser_logs.json")
       util.preprocess_windows("example/ATLAS/training_logs/h1/logs/security_events.txt","mycode/dataset/h1/windows_security_logs.json")
       
       
if __name__ == "__main__":
       preprocess()