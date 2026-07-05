// This file is a design-notes sketch that sits in colonel/src/ but
// isn't ready to build yet — the //go:build ignore tag below keeps
// it out of the toolchain build so stdlib-conformance CI stays green.
// Remove the tag once the quantum package is ready to compile.

//go:build ignore

package quantum

import "git.enigmaneering.org/geese/std"

// Observation pairs a std.Existence with an observed value.
type Observation[TClass any, TValue any] struct {
	Value any
	std.Existence
}

// An Observer is a receive-only channel observing a class of vector values.
type Observer[TClass any, TValue any] <-chan Observation[TClass, TValue]

// An ObservationPoint is a factory for creating an Observer of a class of vector values.
//
// NOTE: This should be created from a Vector or its Vectored result.
type ObservationPoint[TClass any, TValue any] func() Observer[TClass, TValue]

// A Certificate represents a public key derived from provenance.
type Certificate [64]byte

// A Certifiable type holds a vector to a Certificate.
type Certifiable func() Certificate

// Identity holds a vector to an identifier that's runtime Certifiable.
type Identity func() (uint, Certifiable)

// Entangle imprints a Certifiable Identity against a type-classified Vector to a potentially emergent value with Disclosure.
//
// NOTE: To implicitly encrypt the data, please pass Secret[TValue] for TValue (only the outermost constraint will be considered).
func Entangle[TClass any, TValue any](value any) (Vector[TClass, TValue], *Disclosure[TClass, TValue]) {
	// TODO: If value IS a vector, don't recertify it - just expand it's return scope
	panic("not implemented")
}

// A Vector is a thunk to a type-classified value imprinted with Certifiable Identity whenever Vectored.
//
// A "type-classified" value is a means of associating many vectors together by sharing
// a unique referential type while the held type can vary.
type Vector[TClass any, TValue any] func(set ...any) Vectored[TClass, TValue]

// A Vectored type is the structural result of evaluating a Vector's set and/or getter and holds a static
// snapshot of a vector operation's functional output.  This carries a special pattern worth noting:
//
//	" Graceful Fluent Observance "
//
//	var vec Vector[any, int]
//	...
//	if out := vec(42); out.Error() == nil {
//	  obs := out.Observer()
//	  ...
//	}
type Vectored[TClass any, TValue any] struct {
	value            TValue
	identity         Identity
	observationPoint ObservationPoint[TClass, TValue]
	err              error
}

func (v *Vectored[TClass, TValue]) All() (Identity, TValue, ObservationPoint[TClass, TValue], error) {
	return v.identity, v.value, v.observationPoint, v.err
}

func (v *Vectored[TClass, TValue]) Identity() Identity {
	return v.identity
}

func (v *Vectored[TClass, TValue]) ObservationPoint() ObservationPoint[TClass, TValue] {
	return v.observationPoint
}

func (v *Vectored[TClass, TValue]) Value() TValue {
	return v.value
}

func (v *Vectored[TClass, TValue]) Error() error {
	return v.err
}

// A Secret is a vector to a value which has been cryptographically encoded.
type Secret[TValue Measurable[TValue]] []byte

// Decrypt Will either return the unencrypted value or error if Your provenance isn't listed in its Disclosure.
func (s Secret[TValue]) Decrypt() (TValue, error) {
	// Checks the goroutine's identity to see if it has access, then returns it or errors
	panic("not implemented")
}

type Disclosure[TClass any, TValue any] struct {
}

// A Measurable type is anything which can natively be translated into a Measurement and back again.
type Measurable[T any] interface {
	Parse(Measurement) T
	Measure() Measurement
}

type Measurement struct {
}

/**
Diffie-Hellman Seeds:
	The ultimate takeaway of a Diffie-Hellman exchange is that there's private and public values.
So, if our DNA files are just a mathematical number, we could remove a known portion that's derived
from a Diffie-Hellman exchange with a secure key.  Let's say we have a terrabyte long file - we'd
build key 'AGB' at the time of creation between the TPM and the seed using only public values.
Then, we'd tone that key across the entire bit-width and subtract that value out of the file.

To reconstruct, rebuild AGB in a new Diffie-Hellman using the same identity and hardware and you'd
get the missing number needed to mathematically complete the file.  There'd be absolutely ZERO
information constructable until the removed value were added back in, because we'd effectively
be touching every interval width of the data and modifying it - just in a reconstructable fashion.

AGB is built by:
Alice adds Her private key to G -> AG
Bob adds His private key to G -> BG
They exchange these -> Alice(BG), Bob(AG)
Then, both add their private keys into the Other's paired key. -> Alice(BGA), Bob(AGB)
Done

AGB/BGA are interchangeable and secure numbers.

For seeds, this would mean that a seed is distributed as "Value + G".  G cannot be a checksum,
but it can be observed to move to known locations during synthesis to validate the process.
That means that G would act as the shared public value needed to generate the tone, but the
missing hardware key would push that tone into the appropriate position across the index.  Then,
the final resolution should reveal G at the tail end of the number.  If that isn't found, then
the process didn't work and you'd know there was an issue - since you distilled by deciding
upon G and appending it to the end of the data FIRST.
*/
