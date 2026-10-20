package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/hkontrol/dnssd"
	"github.com/hkontrol/hkontroller/log"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// dialServiceInstance lookup dnssd service and make tcp connection
func dialServiceInstance(ctx context.Context, e *dnssd.BrowseEntry, dialTimeout time.Duration) (net.Conn, error) {

	IPs := e.IPs
	sort.Slice(IPs, func(i, j int) bool {
		return IPs[i].To4() != nil // ip4 first
	})

	var firstEstablishedConn net.Conn
	mu := sync.Mutex{}

	// common context
	cc, cancel := context.WithCancel(ctx)
	defer cancel()

	// probe every ip tcpAddr
	wg := sync.WaitGroup{}
	for _, ip := range IPs {
		var tcpAddr string
		if ip.To4() == nil {
			// ipv6 tcpAddr in square brackets
			// [fe80::...%wlp2s0]:51510
			tcpAddr = fmt.Sprintf("[%s%%%s]:%d", ip.String(), e.IfaceName, e.Port)
		} else {
			tcpAddr = fmt.Sprintf("%s:%d", ip.String(), e.Port)
		}

		log.Debug.Println("dialing: ", tcpAddr)

		wg.Add(1)
		go func(tcpAddr string) {
			defer wg.Done()
			// use dialer with parent context to be able to cancel connect
			d := net.Dialer{Timeout: dialTimeout}
			tcpConn, err := d.DialContext(cc, "tcp", tcpAddr)
			if err != nil {
				log.Debug.Println("dial err: ", err)
				return
			}
			log.Debug.Println("dial good")
			mu.Lock()
			defer mu.Unlock()
			if firstEstablishedConn == nil {
				firstEstablishedConn = tcpConn
				cancel() // cancel all other attempts
			}
		}(tcpAddr)
	}

	wg.Wait()

	if firstEstablishedConn == nil {
		return nil, errors.New("no connection available")
	} else {
		return firstEstablishedConn, nil
	}
}

const eventHeader = "EVENT"

// readEvent reads EVENT message from rd. It looks like HTTP response,
// but starts with "EVENT/1.0" instead of "HTTP/1.1", so http.ReadResponse can't parse it.
// Only bytes of this message are consumed, so following response is not lost.
func readEvent(rd *bufio.Reader) (*http.Response, error) {
	tp := textproto.NewReader(rd)
	if _, err := tp.ReadLine(); err != nil { // EVENT/1.0 200 OK
		return nil, err
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(hdr.Get("Content-Length"))
	if err != nil || n < 0 {
		return nil, fmt.Errorf("invalid event content length: %q", hdr.Get("Content-Length"))
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(rd, body); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header(hdr),
		ContentLength: int64(n),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}, nil
}

type conn struct {
	net.Conn

	closed atomic.Bool

	// s and ss are used to encrypt data. s is used to temporarily store the session.
	// After the next read, ss becomes s and the session is encrypted from then on.
	// ------------------------------------------------------------------------------------
	// 2022-02-17 (mah) This workaround is needed because switching to encryption is done
	// after sending a response. But Write() on http.ResponseWriter is not immediate.
	// So therefore we wait until the next read.
	smu sync.Mutex
	ss  *session

	readBuf   io.Reader
	bufReader *bufio.Reader

	// backgroundStop is nil until startLoop is called, then closed when loop stops
	bmu            sync.Mutex
	backgroundStop chan struct{}

	onEvent func(*http.Response) // EVENT callback, when characteristic value updated

	done chan struct{} // closed by device when connection is closed

	// pending receives response for the request in flight, nil if nobody waits.
	// It is buffered, so loop never blocks even if requester is gone.
	pmu     sync.Mutex
	pending chan responseResult
}

type responseResult struct {
	res *http.Response
	err error
}

func newConn(c net.Conn) *conn {
	return &conn{Conn: c, done: make(chan struct{})}
}

func (c *conn) close() {
	c.closed.Store(true)
	c.Conn.Close()
}

func (c *conn) isClosed() bool {
	return c.closed.Load()
}

// startLoop runs loop in background. Returned channel is closed when loop stops.
func (c *conn) startLoop() <-chan struct{} {
	stop := make(chan struct{})
	c.bmu.Lock()
	c.backgroundStop = stop
	c.bmu.Unlock()
	go func() {
		defer close(stop)
		c.loop()
	}()
	return stop
}

// loopStopped returns channel closed when background loop stops,
// or nil if loop was not started.
func (c *conn) loopStopped() <-chan struct{} {
	c.bmu.Lock()
	defer c.bmu.Unlock()
	return c.backgroundStop
}

// expectResponse registers ch to receive response read by loop.
func (c *conn) expectResponse(ch chan responseResult) {
	c.pmu.Lock()
	c.pending = ch
	c.pmu.Unlock()
}

// deliver passes response to waiting request, if any.
func (c *conn) deliver(res *http.Response, err error) {
	c.pmu.Lock()
	ch := c.pending
	c.pending = nil
	c.pmu.Unlock()
	if ch != nil {
		ch <- responseResult{res, err}
	}
}

func (c *conn) SetEventCallback(cb func(*http.Response)) {
	c.onEvent = cb
}

func (c *conn) UpgradeEnc(s *session) {
	c.smu.Lock()
	c.ss = s
	c.smu.Unlock()
}

// Write writes bytes to the connection.
// The written bytes are encrypted when possible.
func (c *conn) Write(b []byte) (int, error) {
	if c.ss == nil {
		n, err := c.Conn.Write(b)
		if err != nil {
			c.close()
			return n, err
		}
		return n, err
	}

	var buf bytes.Buffer
	buf.Write(b)
	enc, err := c.ss.Encrypt(&buf)

	if err != nil {
		c.close()
		return 0, err
	}

	encB, err := io.ReadAll(enc)
	n, err := c.Conn.Write(encB)

	return n, err
}

const (
	packetSize = 0x400
)

// Read reads bytes from the connection.
// The read bytes are decrypted when possible.
func (c *conn) Read(b []byte) (int, error) {
	if c.ss == nil {
		n, err := c.Conn.Read(b)
		if err != nil {
			c.close()
		}
		return n, err
	}

	if c.bufReader == nil {
		c.bufReader = bufio.NewReader(c.Conn)
	}
	if c.readBuf == nil {
		buf, err := c.ss.Decrypt(c.bufReader)
		if err != nil {
			c.close()
			return 0, err
		}

		c.readBuf = buf
	}

	n, err := c.readBuf.Read(b)

	if n < len(b) || err == io.EOF {
		c.readBuf = nil
	}

	return n, err
}

func (c *conn) loop() {
	rd := bufio.NewReader(c)
	for !c.isClosed() {
		b, err := rd.Peek(len(eventHeader)) // len of EVENT string
		if err != nil {
			log.Debug.Println("error reading from connection: ", err)
			c.deliver(nil, err)
			return
		}
		if string(b) == eventHeader {
			res, err := readEvent(rd)
			if err != nil {
				log.Debug.Println("event error: ", err)
				c.deliver(nil, err)
				return
			}

			if c.onEvent != nil {
				c.onEvent(res)
			}

			continue
		} else {
			res, err := http.ReadResponse(rd, nil)
			if err != nil {
				log.Debug.Println("response error: ", err)
				c.deliver(nil, err)
				continue
			}

			// ReadAll here because if response is chunked then on next loop there will be error
			all, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				log.Debug.Println("response body read error: ", err)
				c.deliver(nil, err)
				continue
			}

			// then assign new res.Body
			res.Body = io.NopCloser(bytes.NewReader(all))

			c.deliver(res, nil)
		}
	}
}
