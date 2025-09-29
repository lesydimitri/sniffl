package check

import (
	"bufio"
	"net"
	"testing"
)

func TestSMTPInitializer_Success(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	// Server script
	go func() {
		r := bufio.NewReader(server)
		w := bufio.NewWriter(server)
		// Send greeting
		_, _ = w.WriteString("220 smtp.example.com ESMTP\r\n")
		_ = w.Flush()
		// Read EHLO
		_, _ = r.ReadString('\n')
		// Reply with STARTTLS and final 250 line
		_, _ = w.WriteString("250-smtp.example.com Hello\r\n250-STARTTLS\r\n250 OK\r\n")
		_ = w.Flush()
		// Read STARTTLS command
		_, _ = r.ReadString('\n')
		// Respond ready
		_, _ = w.WriteString("220 Ready\r\n")
		_ = w.Flush()
	}()

	init := NewSMTPInitializer("myhost")
	w := bufio.NewWriter(client)
	r := bufio.NewReader(client)
	if err := init.Initialize(w, r); err != nil {
		t.Fatalf("SMTP Initialize failed: %v", err)
	}
}

func TestIMAPInitializer_Success(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		r := bufio.NewReader(server)
		w := bufio.NewWriter(server)
		// Greeting
		_, _ = w.WriteString("* OK IMAP4rev1 Service Ready\r\n")
		_ = w.Flush()
		// Read A001 STARTTLS
		_, _ = r.ReadString('\n')
		// Respond OK
		_, _ = w.WriteString("A001 OK Begin TLS negotiation now\r\n")
		_ = w.Flush()
	}()

	init := NewIMAPInitializer()
	w := bufio.NewWriter(client)
	r := bufio.NewReader(client)
	if err := init.Initialize(w, r); err != nil {
		t.Fatalf("IMAP Initialize failed: %v", err)
	}
}

func TestPOP3Initializer_Success(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		r := bufio.NewReader(server)
		w := bufio.NewWriter(server)
		// Greeting
		_, _ = w.WriteString("+OK POP3 ready\r\n")
		_ = w.Flush()
		// Read STLS
		_, _ = r.ReadString('\n')
		// Respond +OK
		_, _ = w.WriteString("+OK Begin TLS\r\n")
		_ = w.Flush()
	}()

	init := NewPOP3Initializer()
	w := bufio.NewWriter(client)
	r := bufio.NewReader(client)
	if err := init.Initialize(w, r); err != nil {
		t.Fatalf("POP3 Initialize failed: %v", err)
	}
}

func TestGetProtocolInitializer(t *testing.T) {
	if GetProtocolInitializer("smtp", "h") == nil {
		t.Error("expected smtp initializer")
	}
	if GetProtocolInitializer("imap", "h") == nil {
		t.Error("expected imap initializer")
	}
	if GetProtocolInitializer("pop3", "h") == nil {
		t.Error("expected pop3 initializer")
	}
	if GetProtocolInitializer("unknown", "h") != nil {
		t.Error("expected nil for unknown protocol")
	}
}
