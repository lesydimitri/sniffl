package shared

import (
	"strconv"
	"strings"
)

type StringBuilder struct {
	buf strings.Builder
}

func NewStringBuilder(capacity int) *StringBuilder {
	sb := &StringBuilder{}
	if capacity > 0 {
		sb.buf.Grow(capacity)
	}
	return sb
}

func (sb *StringBuilder) WriteString(s string) {
	sb.buf.WriteString(s)
}

func (sb *StringBuilder) WriteInt(i int) {
	sb.buf.WriteString(strconv.Itoa(i))
}

func (sb *StringBuilder) WriteByte(b byte) error {
	return sb.buf.WriteByte(b)
}

func (sb *StringBuilder) String() string {
	return sb.buf.String()
}


func (sb *StringBuilder) Len() int {
	return sb.buf.Len()
}

func JoinHostPort(host string, port int) string {
	// Always use StringBuilder for consistent performance
	// Estimate capacity: host length + ":" + max 5 digits for port
	sb := NewStringBuilder(len(host) + 8)
	sb.WriteString(host)
	_ = sb.WriteByte(':')
	sb.WriteInt(port)
	return sb.String()
}

func FormatError(operation, target string, err error) string {
	sb := NewStringBuilder(len(operation) + len(target) + 32)
	sb.WriteString(operation)
	sb.WriteString(" failed for ")
	sb.WriteString(target)
	sb.WriteString(": ")
	sb.WriteString(err.Error())
	return sb.String()
}
