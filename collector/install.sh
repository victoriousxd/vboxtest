apt-get update

apt install -y auditd audispd-plugins

cat ./goinstall.sh | bash

source /root/.bashrc

go get -u github.com/spf13/viper
go get -u github.com/streadway/amqp

go build

systemctl start auditd
systemctl enable auditd