FROM ubuntu
RUN apt-get update && apt-get install git python3-pip python-dev build-essential && pip3 install pylint 
