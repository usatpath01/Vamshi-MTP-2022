**MTP - 2 Readme**

The application folder contains all the code for a simple flask application, using postgresql database and gunicorn as a WSGI. You have to deploy this application.
https://faun.pub/deploy-flask-app-with-nginx-using-gunicorn-7fda4f50066a - follow steps in this

test.sh - contains command for running tracee - outputs a json file required by timeline.py. (the json file outputted has syntax errors - Has to corrected manually)
ss.sh - contains command for getting socket statistics

While running tracee run this command (socket statistics)
watch -n0 './ss.sh >> ss.log'

And then after tracee and the abv command are stopped, we run
awk '{$1=$1};!seen[$0]++' ss.log > tmp && mv tmp ss.log

Finally run timeline.py to get the output in a csv file

Order for running - 
1. Application has to be already deployed.
2. service nginx stop; service postgresql stop; service app stop;
3. Run tracee, Run socket statistics
4. service nginx start; service postgresql start; service app start;
5. You can use automater.py to automate using the application
6. Stop tracee and socket statistics
7. Run the awk command.
8. Run timeline.py


**Filetracking**

filedel.py - tracks renames and deletes

filetrack.py - tracks reads and writes

The files to track are currently hardcoded. Change them before running the code.
