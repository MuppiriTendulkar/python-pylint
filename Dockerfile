FROM python:3.7-alpine
RUN apk update
RUN apk add build-base
RUN pip3 install -U pylint
