#!/usr/bin/env bash

chmod +x *.jar
nohup java -jar `pwd`/*.jar >/dev/null 2>&1 &
echo "Press ctrl + C to break ..."
echo ""
echo "Try to start server, please wait."
sleep 3
tail -f  dataexport-core.log