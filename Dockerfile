FROM python:2

RUN apt-get update && apt-get install curl

RUN curl https://get.docker.com | sh

ADD ./requirements.txt /requirements.txt

RUN pip install -r requirements.txt

ADD ./funneld.py /funneld.py

RUN useradd -m -s /usr/bin/funnel-sh -G docker funneld

ENTRYPOINT ["python", "/funneld.py"]
