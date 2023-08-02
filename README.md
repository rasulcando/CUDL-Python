# CUDL-Python
Python Flask Script for User management

Local Setup:
$ mkdir rp_flask_api
$ cd rp_flask_api

$ python -m venv venv
$ source venv/bin/activate
(venv) $

(venv) $ python -m pip install Flask==2.2.2

$ python app.py

This will execute the app

Else install gunicorn and run your app by it for Prod envs

$ gunicorn app-rds:app
