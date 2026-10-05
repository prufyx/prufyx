// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

// Step is the shape of Apply's merge and withdraw steps.
type Step = func(base *Pack, run *Run, rep *Report) (*Pack, map[string]bool, error)

// RealMerge and RealWithdraw are the production steps.
var (
	RealMerge    Step = merge
	RealWithdraw Step = withdraw
)

// SetSteps replaces the steps Apply runs (nil keeps one) and returns the
// function that restores them.
func SetSteps(m, w Step) (restore func()) {
	om, ow := mergeStep, withdrawStep
	if m != nil {
		mergeStep = m
	}
	if w != nil {
		withdrawStep = w
	}
	return func() { mergeStep, withdrawStep = om, ow }
}

// SupersedeStep is the shape of Supersede's planning step.
type SupersedeStep = func(base *Pack, run *Run, rep *SupersedeReport) (*Pack, map[string]bool, map[string]bool, error)

// RealSupersede is the production planning step.
var RealSupersede SupersedeStep = planSupersede

// SetSupersedeStep replaces the planning step and returns the function that
// restores it.
func SetSupersedeStep(s SupersedeStep) (restore func()) {
	o := supersedeStep
	supersedeStep = s
	return func() { supersedeStep = o }
}
