#!/bin/bash 

docker stop $(docker ps -q)
docker rm $(docker ps -a -q)
docker volume rm $(docker volume ls -q)
docker network rm $(docker network ls -q)
python3 docker_starter.py -c 3 -t docker-compose-node.yaml -b docker-compose-boot-node.yaml
docker-compose -f ../sawtooth-explorer/docker-compose.yml up --detach
