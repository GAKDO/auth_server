package com.gakdo.trace.auth.receipt.infra;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Declarables;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.support.converter.SimpleMessageConverter;
import org.springframework.boot.autoconfigure.amqp.SimpleRabbitListenerContainerFactoryConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * trace.events의 trace.record.sealed를 auth-server 큐 trace.auth.receipts로 받는다(contracts events, x-consumers).
 * 계속 실패한 메시지는 trace.dlx로 보내 trace.auth.receipts.dlq에 모은다(다른 서버와 같은 방식).
 */
@Configuration
public class ReceiptAmqpConfig {

    public static final String EXCHANGE = "trace.events";
    public static final String QUEUE = "trace.auth.receipts";
    public static final String DLX = "trace.dlx";
    public static final String DEAD_KEY = "trace.auth.receipts.dead";
    public static final String DLQ = "trace.auth.receipts.dlq";
    public static final String RECORD_SEALED = "trace.record.sealed";

    @Bean
    Declarables receiptTopology() {
        TopicExchange events = new TopicExchange(EXCHANGE, true, false);
        TopicExchange dlx = new TopicExchange(DLX, true, false);
        Queue queue = QueueBuilder.durable(QUEUE)
                .deadLetterExchange(DLX)
                .deadLetterRoutingKey(DEAD_KEY)
                .build();
        Queue dlq = QueueBuilder.durable(DLQ).build();
        Binding sealed = BindingBuilder.bind(queue).to(events).with(RECORD_SEALED);
        Binding dead = BindingBuilder.bind(dlq).to(dlx).with(DEAD_KEY);
        return new Declarables(events, dlx, queue, dlq, sealed, dead);
    }

    /**
     * 리스너는 본문(byte[])을 직접 읽는다. 보낸 쪽의 __TypeId__ 헤더로 클래스를 찾다가 메시지를 버리지 않게
     * 변환하지 않는 변환기를 쓴다(11/4 rental·capture·report에서 겪은 문제).
     */
    @Bean
    SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(
            SimpleRabbitListenerContainerFactoryConfigurer configurer, ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        configurer.configure(factory, connectionFactory);
        factory.setMessageConverter(new SimpleMessageConverter());
        return factory;
    }
}
