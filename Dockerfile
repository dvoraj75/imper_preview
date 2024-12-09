FROM python:3.12-alpine AS evidenta_base

WORKDIR /app

RUN apk update --no-cache && apk add postgresql-dev --no-cache

COPY requirements.txt .

RUN pip install -r requirements.txt

EXPOSE 8000

FROM evidenta_base AS evidenta_dev

COPY requirements-dev.txt .

RUN pip install -r requirements-dev.txt

COPY . .

CMD ["sh", "./bin/entrypoint.sh", "--dev"]

FROM evidenta_base AS evidenta_prod

COPY . .

CMD ["sh", "./bin/entrypoint.sh"]