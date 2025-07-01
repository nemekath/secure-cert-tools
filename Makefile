test:
	python3 -m pytest tests.py test_security_hardening.py -v

lint:
	python3 -m flake8 --max-line-length=120 .

check: lint test

requirements: requirements.txt requirements-dev.txt

requirements-dev.txt: Pipfile.lock
	pipenv requirements --dev > requirements-dev.txt

requirements.txt: Pipfile.lock
	pipenv requirements > requirements.txt

clean:
	-find . -type f -name '*.pyc' -delete
	-rm -rf build dist *.egg-info
	-rm -rf .pytest_cache __pycache__

docker:
docker build -t secure-cert-tools:latest .

docker-run:
docker run -d -p 5555:5555 --name secure-cert-tools secure-cert-tools:latest

docker-logs:
docker logs secure-cert-tools

docker-stop:
docker stop secure-cert-tools
docker rm secure-cert-tools

dev:
	python3 start_server.py --dev

run:
	python3 app.py

.PHONY: clean test lint check docker docker-run docker-logs docker-stop dev run
