#!/bin/bash
# cd /usr/local/energyrecorder/recording-api/
# export PYTHONPATH=.:$PYTHONPATH
# python app.py &

function startInflux(){
        influxd &
        sleep 1
        echo "show databases" | influx -username "$1" -password "$2"|grep NRG
        if [ $? -ne 0 ] ; then
                curl https://raw.githubusercontent.com/bherard/energyrecorder/master/influx/creation.iql|influx
                echo "CREATE USER $1 WITH PASSWORD '"$2"' WITH ALL PRIVILEGES"|influx
                echo "CREATE USER $3 WITH PASSWORD '"$4"'"|influx
                echo "GRANT READ ON NRG TO energyreader"|influx
        else
                echo "Database already exists"
        fi
        if [ ! -f /etc/ssl/influxdb.pem ] ; then
                /usr/local/bin/create-certs.sh
        fi
        grep '\[http\]' /etc/influxdb/influxdb.conf >/dev/null
        if [ $? -ne 0 ] ; then
        cat <<EOF >> /etc/influxdb/influxdb.conf

[http]
enabled = true
auth-enabled = false
https-enabled = false
https-certificate = "/etc/ssl/influxdb.pem"
EOF
        fi
        ps ax|grep influxd|grep -v grep|awk '{print $1}'|xargs kill -9
        influxd &

}

function startUwsgi(){
        cat <<EOF > /etc/uwsgi/conf.d/energyrecorder.ini
[uwsgi]
plugins = python
chdir = /usr/local/energyrecorder/recording-api
module = app
callable = APP
socket = /tmp/recorder.socket
chmod-socket = 777

vacuum = true
die-on-term = true


EOF
        chown uwsgi:uwsgi /etc/uwsgi/conf.d/energyrecorder.ini
        uwsgi --ini /etc/uwsgi/uwsgi.ini &
        sleep 1

}


function startNginx(){
        cat <<EOF > /etc/nginx/conf.d/default.conf
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        location / {
                include uwsgi_params;
                uwsgi_pass unix:/tmp/recorder.socket;
        }

}
server {
        listen 8888 ;
        listen [::]:8888 ;

        location / {
                include uwsgi_params;
                uwsgi_pass unix:/tmp/recorder.socket;
        }

}
EOF
        mkdir -p /run/nginx
        nginx -g "daemon off;"
}


function confApp(){
        if [ ! -f /usr/local/energyrecorder/recording-api/conf/webapp-logging.conf ] ; then
                cp /usr/local/energyrecorder/recording-api/conf/webapp-logging.conf.sample /usr/local/energyrecorder/recording-api/conf/webapp-logging.conf
                mkdir -p /var/log/energyrecorder
                chmod a+w /var/log/energyrecorder
        fi
        if [ ! -f /usr/local/energyrecorder/recording-api/conf/webapp-settings.yaml ] ; then
                cp /usr/local/energyrecorder/recording-api/conf/webapp-settings.yaml.sample /usr/local/energyrecorder/recording-api/conf/webapp-settings.yaml
        fi
}

confApp
startInflux
startUwsgi
startNginx


