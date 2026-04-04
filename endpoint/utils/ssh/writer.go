package ssh

import "io"

// The StringWriter interface defines methods for writing strings and bytes to an underlying writer.
// @property {error} WriteLine - A method that takes a string as input and writes it to the underlying
// writer, followed by a newline character. It returns an error if there was an issue writing the
// string.
// @property {error} Write - The Write method is used to write a string to the StringWriter. It takes a
// string as input and returns an error if any occurred during the write operation.
// @property {error} WriteBytes - The WriteBytes method takes a byte slice as input and writes it to
// the underlying writer. It returns an error if there was an issue writing the bytes.
// @property GetWriter - This method returns an io.Writer interface, which can be used to write data to
// a stream.
type StringWriter interface {
	WriteLine(string) error
	Write(string) error
	WriteBytes([]byte) error
	GetWriter() io.Writer
}

type stringWriter struct {
	w io.Writer
}

// The `WriteLine` method is a function defined on the `stringWriter` struct. It takes a string `s` as
// input and writes it to the underlying writer `w`, followed by a newline character. It returns an
// error if there was an issue writing the string.
func (w *stringWriter) WriteLine(s string) error {
	return w.Write(s + "\n")
}

// The `func (w *stringWriter) Write(s string) error {` is a method defined on the `stringWriter`
// struct. It takes a string `s` as input and writes it to the underlying writer `w`. It returns an
// error if there was an issue writing the string.
func (w *stringWriter) Write(s string) error {
	_, err := w.w.Write([]byte(s))
	return err
}

// The `WriteBytes` method is a function defined on the `stringWriter` struct. It takes a byte slice
// `b` as input and writes it to the underlying writer `w`. It returns an error if there was an issue
// writing the bytes. This method allows you to write raw bytes to the underlying writer.
func (w *stringWriter) WriteBytes(b []byte) error {
	_, err := w.w.Write(b)
	return err
}

// The `GetWriter` method is a function defined on the `stringWriter` struct. It returns an `io.Writer`
// interface, which can be used to write data to a stream. This allows you to access the underlying
// writer and perform write operations directly on it if needed.
func (w *stringWriter) GetWriter() io.Writer {
	return w.w
}
