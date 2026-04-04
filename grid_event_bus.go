package main

import (
	"context"
	"errors"
	"sync"

	"github.com/nats-io/nats.go"
)

type inProcSubscription struct {
	bus     *InProcEventBus
	subject string
	id      int
}

func (s *inProcSubscription) Unsubscribe() error {
	if s == nil || s.bus == nil {
		return nil
	}
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	if handlers, ok := s.bus.subscribers[s.subject]; ok {
		delete(handlers, s.id)
		if len(handlers) == 0 {
			delete(s.bus.subscribers, s.subject)
		}
	}
	return nil
}

type InProcEventBus struct {
	mu          sync.RWMutex
	closed      bool
	nextID      int
	subscribers map[string]map[int]func([]byte)
}

func NewInProcEventBus() *InProcEventBus {
	return &InProcEventBus{
		subscribers: make(map[string]map[int]func([]byte)),
	}
}

func (b *InProcEventBus) Publish(_ context.Context, subject string, payload []byte) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return errors.New("event bus is closed")
	}
	handlers := b.subscribers[subject]
	copied := make([]func([]byte), 0, len(handlers))
	for _, handler := range handlers {
		copied = append(copied, handler)
	}
	b.mu.RUnlock()

	for _, handler := range copied {
		handlerCopy := handler
		payloadCopy := append([]byte(nil), payload...)
		go handlerCopy(payloadCopy)
	}
	return nil
}

func (b *InProcEventBus) Subscribe(subject string, handler func([]byte)) (EventSubscription, error) {
	if handler == nil {
		return nil, errors.New("handler is nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("event bus is closed")
	}
	b.nextID++
	if _, ok := b.subscribers[subject]; !ok {
		b.subscribers[subject] = make(map[int]func([]byte))
	}
	b.subscribers[subject][b.nextID] = handler
	return &inProcSubscription{
		bus:     b,
		subject: subject,
		id:      b.nextID,
	}, nil
}

func (b *InProcEventBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.subscribers = make(map[string]map[int]func([]byte))
	return nil
}

type natsSubscription struct {
	sub *nats.Subscription
}

func (s *natsSubscription) Unsubscribe() error {
	if s == nil || s.sub == nil {
		return nil
	}
	return s.sub.Unsubscribe()
}

type NatsEventBus struct {
	conn *nats.Conn
}

func NewNatsEventBus(url string) (*NatsEventBus, error) {
	conn, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}
	return &NatsEventBus{conn: conn}, nil
}

func (b *NatsEventBus) Publish(_ context.Context, subject string, payload []byte) error {
	if b == nil || b.conn == nil {
		return errors.New("nats connection is nil")
	}
	return b.conn.Publish(subject, payload)
}

func (b *NatsEventBus) Subscribe(subject string, handler func([]byte)) (EventSubscription, error) {
	if b == nil || b.conn == nil {
		return nil, errors.New("nats connection is nil")
	}
	if handler == nil {
		return nil, errors.New("handler is nil")
	}
	sub, err := b.conn.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
	})
	if err != nil {
		return nil, err
	}
	return &natsSubscription{sub: sub}, nil
}

func (b *NatsEventBus) Close() error {
	if b == nil || b.conn == nil {
		return nil
	}
	b.conn.Close()
	return nil
}
