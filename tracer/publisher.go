package tracer

import (
	"context"
	// "net/url"
	// "subtrace.dev/pubsub"
)

var DefaultPublisher = &publisher{ch: make(chan []byte, 4096)}

type publisher struct {
	ch chan []byte
}

func (p *publisher) Loop(ctx context.Context) {
    
}