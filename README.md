# stix-generator
This app is for generate STIX object from STIX event

## Description
`app.py` is for generate all STIX object \
`app_ddos.py` is for generate ddos STIX object

## Config
set the database uri in `app.py` and/or `app_ddos.py`

## Create python virtual environment
```
virtualenv venv
```

## Install dependencies
```
pip install -r requirements.txt
```

## Run app
```
python app.py
or 
python app_ddos.py
```