package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
)

// Publisher writes validated events to named raw topics and a shared DLQ.
type Publisher struct {
	brokers []string
	writers map[string]*kafka.Writer
	dlq     *kafka.Writer
}

func NewPublisher(brokers []string, topics []string, topicDLQ string) (*Publisher, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("at least one kafka broker is required")
	}
	if len(topics) == 0 {
		return nil, fmt.Errorf("at least one raw topic is required")
	}
	writers := make(map[string]*kafka.Writer, len(topics))
	for _, topic := range topics {
		writers[topic] = &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Topic:        topic,
			Balancer:     &kafka.Hash{},
			RequiredAcks: kafka.RequireOne,
			Async:        false,
			BatchTimeout: 10 * time.Millisecond,
		}
	}
	dlq := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topicDLQ,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireOne,
		Async:        false,
		BatchTimeout: 10 * time.Millisecond,
	}
	return &Publisher{brokers: brokers, writers: writers, dlq: dlq}, nil
}

func (p *Publisher) PublishRaw(ctx context.Context, topic string, key, value []byte) error {
	w, ok := p.writers[topic]
	if !ok {
		return fmt.Errorf("unknown topic: %s", topic)
	}
	return w.WriteMessages(ctx, kafka.Message{
		Key:   key,
		Value: value,
		Time:  time.Now().UTC(),
	})
}

func (p *Publisher) PublishDLQ(ctx context.Context, key, value []byte, headers map[string]string) error {
	msg := kafka.Message{
		Key:   key,
		Value: value,
		Time:  time.Now().UTC(),
	}
	for k, v := range headers {
		msg.Headers = append(msg.Headers, kafka.Header{Key: k, Value: []byte(v)})
	}
	return p.dlq.WriteMessages(ctx, msg)
}

func (p *Publisher) Ping(ctx context.Context) error {
	conn, err := kafka.DialContext(ctx, "tcp", p.brokers[0])
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Brokers()
	return err
}

func (p *Publisher) Close() error {
	var first error
	for _, w := range p.writers {
		if err := w.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := p.dlq.Close(); err != nil && first == nil {
		first = err
	}
	return first
}
