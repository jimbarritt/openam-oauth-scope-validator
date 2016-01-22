#!/bin/bash

echo "Deploying to local machine @ [/var/openam/OpenAM-12.0.0-1.war/webapp/WEB-INF/lib/] ..."

cp target/openam-oauth-scope-validators*.jar /var/openam/OpenAM-12.0.0-1.war/webapp/WEB-INF/lib/

ls -lart /var/openam/OpenAM-12.0.0-1.war/webapp/WEB-INF/lib/openam-oauth-scope*.jar
echo "Copied ok. You need to restart OpenAM now"