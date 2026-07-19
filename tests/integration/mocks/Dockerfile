FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi uvicorn "PyJWT[crypto]"
COPY mock_idp.py mock_provider.py /app/
WORKDIR /app
# APP selects which mock to run (mock_idp:app or mock_provider:app)
ENV APP=mock_provider:app PORT=9000
CMD ["sh", "-c", "uvicorn ${APP} --host 0.0.0.0 --port ${PORT}"]
