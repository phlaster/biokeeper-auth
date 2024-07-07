import pika
from config import RABBITMQ_AUTH_USER, RABBITMQ_AUTH_PASS

credentials = pika.PlainCredentials(RABBITMQ_AUTH_USER, RABBITMQ_AUTH_PASS)
rabbitmq_params = pika.ConnectionParameters(host='biokeeper_mq', port=5672,
                                            virtual_host='basic_vhost',
                                            credentials=credentials)


def publish_user_created(id: int, username: str):
    exchange_name = 'users.topic'
    connection = pika.BlockingConnection(rabbitmq_params)
    channel = connection.channel()
    channel.basic_publish(exchange=exchange_name,
                            routing_key='new_user',
                            body=str({"id": id, "username": username}))
    connection.close()