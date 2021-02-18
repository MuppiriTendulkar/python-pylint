FROM ubuntu
RUN apt-get update -y && apt-get install git python3-pip python-dev build-essential -y && pip3 install pylint 
