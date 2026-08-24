FROM python:3.9-slim

WORKDIR /app

RUN pip install flask requests openai

COPY . .

CMD ["python", "app.py"]
