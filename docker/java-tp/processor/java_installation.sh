#!/bin/bash

apt-get update -y -q

apt-get upgrade -y -q

add-apt-repository ppa:webupd8team/java -y -q

apt-get update -y -q

apt-get install oracle-java8-installer -y -q

apt-get install maven -y -q
