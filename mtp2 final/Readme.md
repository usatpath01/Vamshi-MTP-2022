**MTP - 2 Readme**
The application folder contains all the code for a simple flask application, using postgresql database and gunicorn as a WSGI. You have to deploy this application.
https://faun.pub/deploy-flask-app-with-nginx-using-gunicorn-7fda4f50066a - follow steps in this

tracee.sh - contains command for running tracee - outputs a json file required by timeline.py.

format.sh - contains command to format tracee output into JSONL

unique.sh - contains commands to select unique entries in ss command output

timline.py - generate timeline

Commands to Run (Make sure app is deployed correctly, and service app stop/start works as intended)

1. service app stop; service nginx stop; service postgresql stop

2. timeout 70s ./ss.sh gunicorn,nginx,postgres & timeout 70s ./tracee.sh gunicorn,nginx,postgres

3. service app start; service nginx start; service postgresql start

4. ./unique.sh

5. ./format.sh

6. python3 timeline.py
