FROM python:3-alpine
# FROM jhuopensource/semesterly-base:latest

RUN mkdir /code
WORKDIR /code

# Just adding basics
ADD requirements.txt /code/
#ADD ./package.json /code/

# Add everything
ADD . /code/


# Nginx moved out
#COPY ./build/semesterly-nginx.conf /etc/nginx/sites-available/
#RUN rm /etc/nginx/sites-enabled/*
#RUN ln -s /etc/nginx/sites-available/semesterly-nginx.conf /etc/nginx/sites-enabled
#RUN echo "daemon off;" >> /etc/nginx/nginx.conf

# Use environment based config
#COPY ./build/local_settings.py /code/semesterly/local_settings.py

# Add parser script
# COPY ./build/run_parser.sh /code/run_parser.sh

RUN apk add gcc musl-dev libffi-dev xmlsec postgresql-libs postgresql-dev 
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
