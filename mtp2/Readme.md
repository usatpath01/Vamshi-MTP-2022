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
Application has to be already deployed.
service nginx stop; service postgresql stop; service app stop;

Run tracee, Run socket statistics

service nginx start; service postgresql start; service app start;

You can use automater.py to automate using the application

Stop tracee and socket statistics
Run the awk command.
Run the timeline.py


**Filetracking**
filedel.py - tracks renames and deletes
filetrack.py - tracks reads and writes
The files to track are currently hardcoded. Change them before running the code.
