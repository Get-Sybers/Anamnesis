// Package profile discovers fixed-size record arrays in an unlabeled region of
// memory by frame profiling: reshape the byte stream into rows of a candidate
// width and look for columns that are near-constant across rows (a "preamble").
//
// The theory is in docs/research/offline-structure-recovery.md, Section 7. In
// short: a contiguous array of S-byte records tiles the stream so that a field
// at record offset k lands in column k of every row when the frame width equals
// S. A constant or low-variance field (a pool tag, a flag byte, the high bytes
// of a kernel pointer) then shows up as a low-entropy column. Sweeping the frame
// width and scoring per-column invariance therefore recovers the record size and
// the offsets of its constant fields, with no symbols.
//
// This package implements the core of that method:
//
//   - Profile / Fundamental: the width sweep and fundamental-stride selection,
//     scored by per-column byte entropy, with an alignment prior.
//   - Autocorrelation: the cheap prefilter that proposes candidate strides.
//   - BitConstancy: per-column constant-bit fraction, for flag-heavy fields whose
//     byte varies but whose bits do not.
//   - Segment: extent segmentation, bounding an array within a larger region.
//
// It finds contiguous, fixed-stride arrays (the PFN database, page-table pages,
// handle tables); it does not find pool-scattered large structs (_EPROCESS) or
// singletons, which the symbols/list-walk methods handle. Raw dumps are physical
// memory, so a virtually-contiguous array must be linearized through the page
// tables before profiling (Section 7.5); page-table pages are the exception and
// frame cleanly as-is. Calibration against symbol-known images (Section 7.6) is
// the on-target gate.
package profile
