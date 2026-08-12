package supervise

import (
	"context"
	"log"
	"time"
)

func Run(ctx context.Context, name string, fn func(context.Context) error) {
	backoff := 100 * time.Millisecond
	maxBackoff := 5 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		start := time.Now()
		err := fn(ctx)
		if ctx.Err() != nil {
			return
		}

		if time.Since(start) > 30*time.Second {
			backoff = 100 * time.Millisecond // reset backoff if worker ran > 30s
		}

		if err != nil {
			log.Printf("supervisor: worker %s exited with error: %v (restarting in %v)", name, err, backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
