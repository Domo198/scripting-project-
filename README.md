# scripting-project-
exposure checker script

MAIN.

This projects objective is to check the provided ports on the provided IP and collects banners and HTTP responses. the IP is local only (127.0.0.1) so it wont scan any other IP's as it points back to the computer you are using
and only scans the ports that where provided in the project resources (18080, 19090, 20001 and 20002). once the scan is complete it will create three files, a .txt, .csv and .json file with the results of the scan in each.
these files wil be located in the same folder as the code

REQUIREMENTS.
The only requirement that is not built into python is "requests". to set it up type (python -m pip install requests) into the terminal. You can type it onto vscodes terminal when opening the project folder or if you are using a diffrent IDE like i did with pycharm, you type the command into your computers terminal 

HOW TO RUN IT.
to run this project make sure you did the requirements, after, first run local_test_services.py and keep it running, then run exposure_checker.py and you should get an output of 3 open and 1 closed.

EXPECTED RESULT.
It will create 3 files in the projects folder (exposure_report.txt, exposure_report.json and exposure_report.csv) where you can view the analysis of the tests 
