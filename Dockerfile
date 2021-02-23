FROM python:3.8.8-slim-buster

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt
COPY main.py /app/main.py
RUN chmod +x /app/main.py

STOPSIGNAL SIGTERM

ENV LANG=C.UTF-8

RUN adduser --system --uid 1000 --gid 0 appuser
USER 1000

CMD ["/app/main.py"]
