FROM tiangolo/uvicorn-gunicorn:python3.11

LABEL maintainer="Srijan Gupta <gupta.srijan94@gmail.com>"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY ./app /app