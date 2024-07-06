import pika

credentials = pika.PlainCredentials('testuser', 'testpassword')
rabbitmq_params = pika.ConnectionParameters(host='biokeeper_mq', port=5672,
                                            virtual_host='microservices',
                                            credentials=credentials)


def publish_user_created(id: int, username: str):
    exchange_name = 'user.created'
    connection = pika.BlockingConnection(rabbitmq_params)
    channel = connection.channel()
    channel.basic_publish(exchange=exchange_name,
                            routing_key='new_user',
                            body=str({"id": id, "username": username}))
    connection.close()