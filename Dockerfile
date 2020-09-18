FROM python:3.8-alpine

ADD requirements.txt netseption.py /app/

RUN apk add --no-cache --virtual .build-deps gcc musl-dev && \
    pip install -r /app/requirements.txt && \
    apk del .build-deps gcc musl-dev

ENTRYPOINT ['python', '/app/netseption.py']
