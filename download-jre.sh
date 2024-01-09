#!/bin/sh
rm -rf jre
mkdir jre
cd jre
wget https://builds.openlogic.com/downloadJDK/openlogic-openjdk-jre/8u392-b08/openlogic-openjdk-jre-8u392-b08-linux-x64.tar.gz -O jre.tar.gz
tar xvf jre.tar.gz
find . -name "*.jar" | xargs -I {} cp {} .
ls -1a *.jar | xargs -I {} unzip {}
