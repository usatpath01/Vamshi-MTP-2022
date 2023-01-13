# Vamshi-MTP-2022
# Extracting the source code files (python) from image and converting them to executables
Given image name already in system

Run the following command
docker save IMG_NAME > IMG_NAME.zip and unzip the file
python3 extractor.py IMG_NAME

Layer Ids corresponding to copy instructions will be printed
Unzip the tar file present corresponding to that layer inside the output directory

A new directory 'output' which contains part of the filesystem which has all the files copied using COPY is created.

# Converting to executable

Run the following commands
python3 -m venv IMG_NAME-venv
source IMG_NAME-venv/bin/activate
pip install -r FILEPATH_TO_REQUIREMENTS.TXT
pyinstaller --onefile --paths IMG_NAME-venv/lib/python3.7/site-packages FILEPATH_TO_MAINPY FILE

Note: --paths flag is used to give location of packages installed in location other than default.
