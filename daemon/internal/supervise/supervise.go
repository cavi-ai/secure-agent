package supervise

import (
	"context"
	"log"
	"time"
)

const (
	// minHealthyRun is how long a worker must run before a failure is treated
	// as transient. A worker that dies sooner than this counts as a fast
	// failure.
	minHealthyRun = 10 * time.Second
	// maxFastFailures is how many consecutive fast failures are tolerated
	// before the supervisor gives up and stops restarting the worker.
	maxFastFailures = 5
)

// Run supervises a worker, restarting it with exponential backoff when it exits
// with an error. A worker that keeps failing quickly (e.g. a collector whose
// underlying tool is unavailable, like eslogger without the Endpoint Security
// entitlement) is abandoned after maxFastFailures instead of being restarted
// forever, which would otherwise spin the CPU and spam the log every few
// seconds. Giving up only stops that one worker; the rest of the daemon keeps
// running.
func Run(ctx context.Context, name string, fn func(context.Context) error) {
	backoff := 100 * time.Millisecond
	maxBackoff := 5 * time.Second
	fastFailures := 0

	for {
		if ctx.Err() != nil {
			return
		}

		start := time.Now()
		err := fn(ctx)
		if ctx.Err() != nil {
			return
		}

		if time.Since(start) >= minHealthyRun {
			// Worker was healthy for a while: treat this exit as a transient
			// blip and reset the backoff and fast-failure counter.
			backoff = 100 * time.Millisecond
			fastFailures = 0
		} else {
			fastFailures++
		}

		if err != nil {
			log.Printf("supervisor: worker %s exited with error: %v (restarting in %v)", name, err, backoff)
		}

		if fastFailures >= maxFastFailures {
			log.Printf("supervisor: worker %s failed %d times in quick succession; giving up (not restarting this session)", name, fastFailures)
			return
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
