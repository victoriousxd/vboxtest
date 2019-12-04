package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/streadway/amqp"
	"log"
	"strconv"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

type rabbitMQ struct {
	ch *amqp.Channel
	conn *amqp.Connection
	exchange string
}

func (rabbit *rabbitMQ) newRabbit(userName string, password string, address string, port int, exchange string, ssl bool  ) {
	var err error
	secure := ""

	if(ssl){
		secure = "s"
	}

	rabbit.conn, err = amqp.Dial("amqp" + secure + "://" + userName + ":" + password + "@" + address + ":"  + strconv.Itoa(port) +"/")
	failOnError(err, "Failed to connect to RabbitMQ")

	rabbit.ch, err = rabbit.conn.Channel()
	failOnError(err, "Failed to open a channel")

	err = rabbit.ch.ExchangeDeclare(
		 exchange,
		"fanout",
		false,
		false,
		false,
		false,
		nil)

	failOnError(err, "Failed to declare an exchange")

	rabbit.exchange = exchange
}

func (rabbit rabbitMQ) Close() error {
	err := rabbit.conn.Close()
	if err != nil {
		return err
	}

	err = rabbit.ch.Close()
	if err != nil {
		return err
	}

	return nil
}

func (rabbit rabbitMQ) Write(body []byte) (int, error){
	rabbit.ch.Publish(
		rabbit.exchange,     // exchange
		"hello", // routing key
		false,  // mandatory
		false,  // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})

	return len(body), nil
}

func createRabbitOutput(config *viper.Viper) (*rabbitMQ, error) {

	address := config.GetString("output.RabbitMQ.address")
	port := config.GetInt("output.RabbitMQ.port")
	userName := config.GetString("output.RabbitMQ.username")
	password := config.GetString("output.RabbitMQ.password")
	exchange := config.GetString("output.RabbitMQ.exchange")
	ssl := config.GetBool("output.RabbitMQ.ssl")

	if address == "" {
		return nil, fmt.Errorf("Output address for rabbitMQ must be set")
	}

	rabbit := &rabbitMQ{
		ch: nil,
		conn: nil,
		exchange:  exchange,
	}


	rabbit.newRabbit(userName,password,address,port, exchange, ssl)


	return rabbit, nil
}


