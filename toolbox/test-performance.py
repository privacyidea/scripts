#!/opt/privacyidea/bin/python
import requests
import time
import urllib3
urllib3.disable_warnings()
import statistics

PI_SERVER = "https://10.0.4.225/"
USER = "user"
PASS = "pass"
VERIFY_TLS = False

times = []

for i in range(1, 10):
    otp = PASS

    start = time.time()
    r = requests.post('{0!s}/validate/check'.format(PI_SERVER), verify=VERIFY_TLS,
                      data={"user": USER, "pass": otp})
    end = time.time()
    diff = end - start
    print("{0:0>3} : {1!s} : {2:.4f}".format(i, r.json().get("result").get("value"), diff))
    times.append(diff)

print("The median time for one request is {0!s}.".format(statistics.median(times)))
print("The slowest request took {0!s} seconds.".format(max(times)))
print("The fastest request took {0!s} seconds.".format(min(times)))
print("The standard deviation is {0!s} seconds.".format(statistics.stdev(times)))
