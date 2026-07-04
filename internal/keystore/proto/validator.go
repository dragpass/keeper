// validator.go — interface that proto Request types implement for self-validation.
//
// The keystore root dispatcher's process[T] helper calls it via a type
// assertion (`any(&req).(Validator)`). Empty payload types (e.g. PingRequest
// in envelope.go) don't implement Validate(), so the type assertion returns
// false and validation is skipped.

package proto

// Validator is the interface that proto Request types implement for
// self-validation.
type Validator interface {
	Validate() error
}
