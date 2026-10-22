package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/shabunin/dnssd"
	"github.com/shabunin/hkontroller/log"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// dialAddrs returns tcp addresses of all entries, ip4 first.
// IPv6 addresses get zone of interface they were discovered on.
func dialAddrs(entries []dnssd.BrowseEntry) []string {
	var addrs4, addrs6 []string
	seen := make(map[string]bool)
	for _, e := range entries {
		for _, ip := range e.IPs {
			var tcpAddr string
			if ip.To4() == nil {
				// ipv6 tcpAddr in square brackets
				// [fe80::...%wlp2s0]:51510
				tcpAddr = fmt.Sprintf("[%s%%%s]:%d", ip.String(), e.IfaceName, e.Port)
			} else {
				tcpAddr = fmt.Sprintf("%s:%d", ip.String(), e.Port)
			}
			if seen[tcpAddr] {
				continue
			}
			seen[tcpAddr] = true
			if ip.To4() == nil {
				addrs6 = append(addrs6, tcpAddr)
			} else {
				addrs4 = append(addrs4, tcpAddr)
			}
		}
	}
	return append(addrs4, addrs6...)
}

// dialServiceInstance probes every address of dnssd entries and returns first established tcp connection
func dialServiceInstance(ctx context.Context, entries []dnssd.BrowseEntry, dialTimeout time.Duration) (net.Conn, error) {

	var firstEstablishedConn net.Conn
	mu := sync.Mutex{}

	// common context
	cc, cancel := context.WithCancel(ctx)
	defer cancel()

	// probe every ip tcpAddr
	wg := sync.WaitGroup{}
	for _, tcpAddr := range dialAddrs(entries) {
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
			} else {
				tcpConn.Close() // another attempt was faster
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

	readBuf   *bytes.Buffer // decrypted data of last packet not read yet
	bufReader *bufio.Reader

	// rd reads responses and events. Pairing requests and background loop share it,
	// so bytes buffered by one are not lost for the other.
	rd *bufio.Reader

	// backgroundStop is nil until startLoop is called, then closed when loop stops
	bmu            sync.Mutex
	backgroundStop chan struct{}
	loopErr        error // why loop stopped, set before backgroundStop is closed

	onEvent func(*http.Response) // EVENT callback, when characteristic value updated

	done chan struct{} // closed by device when connection is closed

	// waiting holds response channels of sent requests, in order.
	// Accessory answers requests in the same order and responses have no ids,
	// so late response of timed out request is matched to its own request.
	// Channels are buffered, so loop never blocks even if requester is gone.
	pmu     sync.Mutex
	waiting []chan responseResult
}

type responseResult struct {
	res *http.Response
	err error
}

func newConn(c net.Conn) *conn {
	cc := &conn{Conn: c, done: make(chan struct{})}
	cc.rd = bufio.NewReader(cc)
	return cc
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
		err := c.loop()
		c.bmu.Lock()
		c.loopErr = err
		c.bmu.Unlock()
		close(stop)
	}()
	return stop
}

// loopError returns error which stopped background loop,
// nil if it is still running or connection was closed.
func (c *conn) loopError() error {
	c.bmu.Lock()
	defer c.bmu.Unlock()
	return c.loopErr
}

// loopStopped returns channel closed when background loop stops,
// or nil if loop was not started.
func (c *conn) loopStopped() <-chan struct{} {
	c.bmu.Lock()
	defer c.bmu.Unlock()
	return c.backgroundStop
}

// expectResponse returns channel receiving response to the next request sent.
func (c *conn) expectResponse() chan responseResult {
	ch := make(chan responseResult, 1)
	c.pmu.Lock()
	c.waiting = append(c.waiting, ch)
	c.pmu.Unlock()
	return ch
}

// deliver passes response to the oldest waiting request.
func (c *conn) deliver(res *http.Response, err error) {
	c.pmu.Lock()
	if len(c.waiting) == 0 {
		c.pmu.Unlock()
		log.Debug.Println("response without request: ", err)
		return
	}
	ch := c.waiting[0]
	c.waiting[0] = nil
	c.waiting = c.waiting[1:]
	c.pmu.Unlock()
	ch <- responseResult{res, err}
}

func (c *conn) SetEventCallback(cb func(*http.Response)) {
	c.onEvent = cb
}

func (c *conn) UpgradeEnc(s *session) {
	c.smu.Lock()
	c.ss = s
	c.smu.Unlock()
}

func (c *conn) session() *session {
	c.smu.Lock()
	defer c.smu.Unlock()
	return c.ss
}

// Write writes bytes to the connection.
// The written bytes are encrypted when possible.
func (c *conn) Write(b []byte) (int, error) {
	ss := c.session()
	if ss == nil {
		n, err := c.Conn.Write(b)
		if err != nil {
			c.close()
		}
		return n, err
	}

	enc, err := ss.Encrypt(bytes.NewReader(b))
	if err != nil {
		c.close()
		return 0, err
	}

	// counter is already advanced, so packets not written
	// would make accessory fail to decrypt everything after them
	if _, err := io.Copy(c.Conn, enc); err != nil {
		c.close()
		return 0, err
	}

	return len(b), nil
}

const (
	packetSize = 0x400
)

// Read reads bytes from the connection.
// The read bytes are decrypted when possible.
func (c *conn) Read(b []byte) (int, error) {
	ss := c.session()
	if ss == nil {
		n, err := c.Conn.Read(b)
		if err != nil {
			c.close()
		}
		return n, err
	}

	if c.bufReader == nil {
		c.bufReader = bufio.NewReader(c.Conn)
	}
	// empty buffer would return io.EOF, so next packet is read instead
	for c.readBuf == nil || c.readBuf.Len() == 0 {
		buf, err := ss.Decrypt(c.bufReader)
		if err != nil {
			c.close()
			return 0, err
		}

		c.readBuf = buf
	}

	return c.readBuf.Read(b)
}

func (c *conn) loop() error {
	rd := c.rd
	for !c.isClosed() {
		b, err := rd.Peek(len(eventHeader)) // len of EVENT string
		if err != nil {
			log.Debug.Println("error reading from connection: ", err)
			c.deliver(nil, err)
			return err
		}
		if string(b) == eventHeader {
			res, err := readEvent(rd)
			if err != nil {
				log.Debug.Println("event error: ", err)
				c.deliver(nil, err)
				return err
			}

			if c.onEvent != nil {
				c.onEvent(res)
			}

			continue
		} else {
			// after malformed response position in stream is unknown,
			// following responses can't be trusted, so loop stops and connection is closed
			res, err := http.ReadResponse(rd, nil)
			if err != nil {
				log.Debug.Println("response error: ", err)
				c.deliver(nil, err)
				return err
			}

			// ReadAll here because if response is chunked then on next loop there will be error
			all, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				log.Debug.Println("response body read error: ", err)
				c.deliver(nil, err)
				return err
			}

			// then assign new res.Body
			res.Body = io.NopCloser(bytes.NewReader(all))

			c.deliver(res, nil)
		}
	}
	return nil
}
