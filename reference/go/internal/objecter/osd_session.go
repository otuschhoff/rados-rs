package objecter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/otuschhoff/go-librados/internal/maps"
	"github.com/otuschhoff/go-librados/internal/msgr"
	"github.com/otuschhoff/go-librados/internal/osd"
	"github.com/otuschhoff/go-librados/internal/protocol"
)

type osdSession struct {
	raw        osdTransport
	limits     osd.Limits
	ackTimeout time.Duration

	mu            sync.Mutex
	backoffs      map[uint64]osd.Backoff
	changed       chan struct{}
	err           error
	notifications chan osd.WatchNotification
}

type osdTransport interface {
	Submit(context.Context, msgr.Message) (msgr.Message, error)
	SubmitAdmitted(context.Context, msgr.Message, func()) (msgr.Message, error)
	Send(context.Context, msgr.Message) error
	Incoming() <-chan msgr.Message
	Terminal() <-chan error
	Done() <-chan struct{}
	Stop()
}

func newOSDSession(raw osdTransport, limits osd.Limits, ackTimeout time.Duration) *osdSession {
	session := &osdSession{raw: raw, limits: limits, ackTimeout: ackTimeout, backoffs: make(map[uint64]osd.Backoff), changed: make(chan struct{}), notifications: make(chan osd.WatchNotification, 128)}
	go session.receive()
	return session
}

func (session *osdSession) Notifications() <-chan osd.WatchNotification { return session.notifications }

func (session *osdSession) NotificationError() error {
	return session.failure(msgr.ErrSessionClosed)
}

func (session *osdSession) Submit(ctx context.Context, message msgr.Message) (msgr.Message, error) {
	return session.raw.Submit(ctx, message)
}

func (session *osdSession) SubmitTarget(ctx context.Context, pg maps.PG, object osd.HObject, message msgr.Message) (msgr.Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		session.mu.Lock()
		if session.err != nil {
			err := session.err
			session.mu.Unlock()
			return msgr.Message{}, err
		}
		blocked := false
		for _, backoff := range session.backoffs {
			if backoff.PG == pg && backoff.Contains(object) {
				blocked = true
				break
			}
		}
		if !blocked {
			var unlock sync.Once
			result, err := session.raw.SubmitAdmitted(ctx, message, func() { unlock.Do(session.mu.Unlock) })
			unlock.Do(session.mu.Unlock)
			if err != nil {
				err = errors.Join(err, session.failure(err))
			}
			return result, err
		}
		changed := session.changed
		session.mu.Unlock()
		select {
		case <-ctx.Done():
			return msgr.Message{}, ctx.Err()
		case <-session.raw.Done():
			return msgr.Message{}, session.failure(msgr.ErrSessionClosed)
		case <-changed:
		}
	}
}

func (session *osdSession) Stop() {
	session.raw.Stop()
}

func (session *osdSession) Wait(ctx context.Context, pg maps.PG, object osd.HObject) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		session.mu.Lock()
		if session.err != nil {
			err := session.err
			session.mu.Unlock()
			return err
		}
		blocked := false
		for _, backoff := range session.backoffs {
			if backoff.PG == pg && backoff.Contains(object) {
				blocked = true
				break
			}
		}
		if !blocked {
			session.mu.Unlock()
			return nil
		}
		changed := session.changed
		session.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-session.raw.Done():
			return session.failure(msgr.ErrSessionClosed)
		case <-changed:
		}
	}
}

func (session *osdSession) receive() {
	defer close(session.notifications)
	for {
		select {
		case message, ok := <-session.raw.Incoming():
			if !ok {
				session.fail(msgr.ErrSessionClosed)
				return
			}
			if message.Header.Type == protocol.MessageOSDMap {
				session.fail(ErrStaleMap)
				session.raw.Stop()
				return
			}
			if message.Header.Type == protocol.MessageWatchNotify {
				notification, err := osd.DecodeWatchNotification(message, session.limits)
				if err != nil {
					session.fail(err)
					session.raw.Stop()
					return
				}
				select {
				case session.notifications <- notification:
				default:
					session.fail(msgr.ErrQueueSaturated)
					session.raw.Stop()
					return
				}
				continue
			}
			if message.Header.Type != protocol.MessageOSDBackoff {
				continue
			}
			backoff, err := osd.DecodeBackoff(message, session.limits)
			if err != nil {
				session.fail(err)
				session.raw.Stop()
				return
			}
			if backoff.Operation == osd.BackoffBlock {
				session.update(func() { session.backoffs[backoff.ID] = backoff })
				ack, err := osd.EncodeBackoffAcknowledgment(backoff, session.limits)
				if err == nil {
					ctx, cancel := context.WithTimeout(context.Background(), session.ackTimeout)
					err = session.raw.Send(ctx, ack)
					cancel()
				}
				if err != nil {
					session.fail(err)
					session.raw.Stop()
					return
				}
			} else {
				session.update(func() { delete(session.backoffs, backoff.ID) })
			}
		case <-session.raw.Done():
			err := msgr.ErrSessionClosed
			select {
			case terminal := <-session.raw.Terminal():
				if terminal != nil {
					err = terminal
				}
			default:
			}
			session.fail(err)
			return
		case err, ok := <-session.raw.Terminal():
			if !ok || err == nil {
				err = msgr.ErrSessionClosed
			}
			session.fail(err)
			session.raw.Stop()
			return
		}
	}
}

func (session *osdSession) update(change func()) {
	session.mu.Lock()
	change()
	close(session.changed)
	session.changed = make(chan struct{})
	session.mu.Unlock()
}

func (session *osdSession) fail(err error) {
	if err == nil {
		err = errors.New("OSD session failed")
	}
	session.mu.Lock()
	if session.err == nil {
		session.err = err
		close(session.changed)
		session.changed = make(chan struct{})
	}
	session.mu.Unlock()
}

func (session *osdSession) failure(fallback error) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.err != nil {
		return session.err
	}
	return fallback
}
