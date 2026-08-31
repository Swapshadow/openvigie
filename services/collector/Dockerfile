FROM python:3.13-slim

WORKDIR /app

COPY collector.py ./collector.py

RUN mkdir -p /data && useradd --system --uid 10001 openvigie && chown -R openvigie:openvigie /app /data

USER openvigie

EXPOSE 8787

CMD ["python", "-u", "collector.py"]
