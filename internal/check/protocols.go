package check

import (
	"bufio"
	"fmt"
	"strings"
)

type SMTPInitializer struct {
	ehloHostname string
}

func NewSMTPInitializer(ehloHostname string) *SMTPInitializer {
	return &SMTPInitializer{ehloHostname: ehloHostname}
}

func (s *SMTPInitializer) Initialize(w *bufio.Writer, r *bufio.Reader) error {
	if _, err := r.ReadString('\n'); err != nil {
		return fmt.Errorf("failed to read SMTP server greeting: %w", err)
	}

	if _, err := fmt.Fprintf(w, "EHLO %s\r\n", s.ehloHostname); err != nil {
		return fmt.Errorf("failed to write EHLO command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush EHLO command: %w", err)
	}
	starttlsSupported := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read SMTP EHLO response: %w", err)
		}
		if strings.Contains(line, "STARTTLS") {
			starttlsSupported = true
		}
		if strings.HasPrefix(line, SMTPStatusOK+" ") {
			break
		}
	}

	if !starttlsSupported {
		return fmt.Errorf("SMTP server does not support STARTTLS extension")
	}

	// Send STARTTLS command
	if _, err := fmt.Fprint(w, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("failed to write STARTTLS command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush STARTTLS command: %w", err)
	}

	// Read STARTTLS response
	resp, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read SMTP STARTTLS response: %w", err)
	}
	if !strings.HasPrefix(resp, SMTPStatusReady) {
		return fmt.Errorf("SMTP STARTTLS command rejected with response: %s", strings.TrimSpace(resp))
	}

	return nil
}

// IMAPInitializer handles IMAP STARTTLS negotiation
type IMAPInitializer struct{}

// NewIMAPInitializer creates a new IMAP initializer
func NewIMAPInitializer() *IMAPInitializer {
	return &IMAPInitializer{}
}

// Initialize performs IMAP STARTTLS negotiation
func (i *IMAPInitializer) Initialize(w *bufio.Writer, r *bufio.Reader) error {
	// Read server greeting
	if _, err := r.ReadString('\n'); err != nil {
		return fmt.Errorf("failed to read IMAP server greeting: %w", err)
	}

	// Send STARTTLS command
	if _, err := fmt.Fprint(w, "A001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("failed to write IMAP STARTTLS command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush IMAP STARTTLS command: %w", err)
	}

	// Read STARTTLS response
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read IMAP STARTTLS response: %w", err)
		}
		upperLine := strings.ToUpper(line)
		if strings.HasPrefix(upperLine, "A001 ") {
			if strings.Contains(upperLine, "OK") {
				return nil
			}
			return fmt.Errorf("IMAP STARTTLS command rejected: %s", strings.TrimSpace(line))
		}
	}
}

// POP3Initializer handles POP3 STLS negotiation
type POP3Initializer struct{}

// NewPOP3Initializer creates a new POP3 initializer
func NewPOP3Initializer() *POP3Initializer {
	return &POP3Initializer{}
}

// Initialize performs POP3 STLS negotiation
func (p *POP3Initializer) Initialize(w *bufio.Writer, r *bufio.Reader) error {
	// Read server greeting
	if _, err := r.ReadString('\n'); err != nil {
		return fmt.Errorf("failed to read POP3 server greeting: %w", err)
	}

	// Send STLS command
	if _, err := fmt.Fprint(w, "STLS\r\n"); err != nil {
		return fmt.Errorf("failed to write POP3 STLS command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush POP3 STLS command: %w", err)
	}

	// Read STLS response
	resp, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read POP3 STLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "+OK") {
		return fmt.Errorf("POP3 STLS command rejected with response: %s", strings.TrimSpace(resp))
	}

	return nil
}

// ProtocolInitializerFunc defines the function signature for protocol initialization
type ProtocolInitializerFunc func(w *bufio.Writer, r *bufio.Reader) error

// GetProtocolInitializer returns the appropriate initializer for the given protocol
func GetProtocolInitializer(protocol, hostname string) ProtocolInitializerFunc {
	switch protocol {
	case "smtp":
		initializer := NewSMTPInitializer(hostname)
		return initializer.Initialize
	case "imap":
		initializer := NewIMAPInitializer()
		return initializer.Initialize
	case "pop3":
		initializer := NewPOP3Initializer()
		return initializer.Initialize
	default:
		return nil
	}
}
