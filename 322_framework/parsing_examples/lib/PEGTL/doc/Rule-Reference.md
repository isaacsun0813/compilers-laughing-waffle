# Rule Reference

This page contains brief descriptions of all PEGTL rule and combinator classes.

The information about how much input is consumed by the rules only applies when the rules succeed.
Otherwise there are two failure modes with different requirements.

- *Local failure* is when a rule returns `false` and the rule **must** generally rewind the input to where its match attempt started.
- *Global failure* is when a rule throws an exception (usually of type `tao::parse_error`)(usually via the control-class' `raise()` function).

Since an exception, by default, aborts a parsing run -- hence the term "global failure" -- there are no assumptions or requirements for the throwing rule to rewind the input.

On the other hand a local failure will frequently lead to back-tracking, i.e. the attempt to match a different rule at the same position in the input, wherefore rules that were previously attempted at the same position must rewind back to where they started in preparation of the next attempt.

Note that in some cases it is not necessary to actually rewind on local failure, see the description of the [rewind_mode](Rules-and-Grammars.md#modes) in the section on [how to implement custom rules](Rules-and-Grammars.md#creating-new-rules).

## Equivalence

Some rule classes are said to be *equivalent to* a combination of other rules.
Here, *equivalence* is with respect to which inputs are matched, but not (necessarily) how the rule is implemented.

For rules other than `must<>` that contain "must" in their name, rule equivalence shows which rule will be used to call the control class' `raise()` function when certain sub-rules fail to match.

## Implementation

The "meta data and implementation mapping" section of each rule's description shows both how the rule is implemented and what the [meta data](Meta-Data-and-Visit.md) looks like.
When the list of sub-rules is empty then the definition of `subs_t` is omitted from the description.

## Parameter Packs

The documentation will use [(template parameter) packs](https://en.cppreference.com/w/cpp/language/parameter_pack) when zero-or-more or one-or-more of a (template) parameter are allowed.
For example `seq< R... >` accepts zero-or-more template parameters.
In the zero case, i.e. `seq<>`, we describe `R` as "empty".
When at least one parameter is given, i.e. `seq< A >` or `seq< A, B, C >`, `R` is "non-empty".

## Contents

* [Meta Rules](#meta-rules)
* [Combinators](#combinators)
* [Convenience](#convenience)
* [Action Rules](#action-rules)
* [Atomic Rules](#atomic-rules)
* [ASCII Rules](#ascii-rules)
* [Unicode Rules](#unicode-rules)
  * [ICU Support](#icu-support)
  * [Basic ICU Rules](#basic-icu-rules)
  * [ICU Rules for Binary Properties](#icu-rules-for-binary-properties)
  * [ICU Rules for Enumerated Properties](#icu-rules-for-enumerated-properties)
  * [ICU Rules for Value Properties](#icu-rules-for-value-properties)
* [Binary Rules](#binary-rules)
* [Full Index](#full-index)

## Meta Rules

These rules are in namespace `tao::pegtl`.

###### `action< A, R... >`

* [Equivalent] to `seq< R... >`, but:
* Uses the given class template `A` for [actions](Actions-and-States.md).
* Does not `enable` or `disable` actions while matching `R...`.
* [Meta data] and [implementation] mapping:
  - `action< A >::rule_t` is `internal::success`
  - `action< A, R >::rule_t` is `internal::action< A, R >`
  - `action< A, R >::subs_t` is `type_list< R >`
  - `action< A, R... >::rule_t` is `internal::action< A, internal::seq< R... > >`
  - `action< A, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `control< C, R... >`

* [Equivalent] to `seq< R... >`, but:
* Uses the given class template `C` as [control class](Control-and-Debug.md).
* [Meta data] and [implementation] mapping:
  - `control< C >::rule_t` is `internal::success`
  - `control< C, R >::rule_t` is `internal::control< C, R >`
  - `control< C, R >::subs_t` is `type_list< R >`
  - `control< C, R... >:rule_t` is `internal::control< C, internal::seq< R... > >`
  - `control< C, R... >:subs_t` is `type_list< internal::seq< R... > >`

###### `disable< R... >`

* [Equivalent] to `seq< R... >`, but:
* Disables all actions.
* [Meta data] and [implementation] mapping:
  - `disable<>::rule_t` is `internal::success`
  - `disable< R >::rule_t` is `internal::disable<, R >`
  - `disable< R >::subs_t` is `type_list< R >`
  - `disable< R... >::rule_t` is `internal::disable< internal::seq< R... > >`
  - `disable< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `discard`

* [Equivalent] to `success`, but:
* Calls the input's `discard()` member function.
* Must not be used where backtracking to before the `discard` might occur and/or nested within a rule for which an action with input can be called.
* See [Incremental Input] for details.
* [Meta data] and [implementation] mapping:
  - `discard::rule_t` is `internal::discard`

###### `enable< R... >`

* [Equivalent] to `seq< R... >`, but:
* Enables all actions (if any).
* [Meta data] and [implementation] mapping:
  - `enable<>::rule_t` is `internal::success`
  - `enable< R >::rule_t` is `internal::enable< R >`
  - `enable< R >::subs_t` is `type_list< R >`
  - `enable< R... >::rule_t` is `internal::enable< internal::seq< R... > >`
  - `enable< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `require< Num >`

* Succeeds if at least `Num` further input bytes are available.
* With [Incremental Input] reads the bytes into the buffer.
* [Meta data] and [implementation] mapping:
  - `require< 0 >::rule_t` is `internal::success`
  - `require< N >::rule_t` is `internal::require< N >`

###### `state< S, R... >`

* [Equivalent] to `seq< R... >`, but:
* Replaces all state arguments with a new instance `s` of type `S`.
* `s` is constructed with the input and all previous states as arguments.
* If `seq< R... >` succeeds then `s.success()` is called with the input after the match and all previous states as arguments.
* [Meta data] and [implementation] mapping:
  - `state< S >::rule_t` is `internal::success`
  - `state< S, R >::rule_t` is `internal::state< S, R >`
  - `state< S, R >::subs_t` is `type_list< R >`
  - `state< S, R... >::rule_t` is `internal::state< S, internal::seq< R... > >`
  - `state< S, R... >::subs_t` is `type_list< internal::seq< R... > >`

## Combinators

Combinators (or combinator rules) are rules that combine (other) rules into new ones.

These are the classical **PEG** combinator rules and are defined in namespace `tao::pegtl`.

###### `at< R... >`

* PEG **and-predicate** &*e*
* Succeeds if and only if `seq< R... >` would succeed.
* Consumes nothing, i.e. rewinds after matching.
* Disables all actions.
* [Meta data] and [implementation] mapping:
  - `at<>::rule_t` is `internal::success`
  - `at< R >::rule_t` is `internal::at< R >`
  - `at< R >::subs_t` is `type_list< R >`
  - `at< R... >::rule_t` is `internal::at< internal::seq< R... > >`
  - `at< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `not_at< R... >`

* PEG **not-predicate** !*e*
* Succeeds if and only if `seq< R... >` would **not** succeed.
* Consumes nothing, i.e. rewinds after matching.
* Disables all actions.
* [Meta data] and [implementation] mapping:
  - `not_at<>::rule_t` is `internal::failure`
  - `not_at< R >::rule_t` is `internal::not_at< R >`
  - `not_at< R >::subs_t` is `type_list< R >`
  - `not_at< R... >::rule_t` is `internal::not_at< internal::seq< R... > >`
  - `not_at< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `opt< R... >`

* PEG **optional** *e*?
* Optional `seq< R... >`, i.e. attempt to match `seq< R... >` and signal success regardless of the result.
* [Equivalent] to `sor< seq< R... >, success >`.
* [Meta data] and [implementation] mapping:
  - `opt<>::rule_t` is `internal::success`
  - `opt< R >::rule_t` is `internal::opt< R >`
  - `opt< R >::subs_t` is `type_list< R >`
  - `opt< R... >::rule_t` is `internal::opt< internal::seq< R... > >`
  - `opt< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `plus< R... >`

* PEG **one-or-more** *e*+
* Matches `seq< R... >` as often as possible and succeeds if it matches at least once.
* [Equivalent] to `rep_min< 1, R... >`.
* `R` must be a non-empty rule pack.
* [Meta data] and [implementation] mapping:
  - `plus< R >::rule_t` is `internal::plus< R >`
  - `plus< R >::subs_t` is `type_list< R >`
  - `plus< R... >::rule_t` is `internal::plus< internal::seq< R... > >`
  - `plus< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `seq< R... >`

* PEG **sequence** *e*<sub>1</sub> *e*<sub>2</sub>
* Sequence or *conjunction* of rules.
* Matches the given rules `R...` in the given order.
* Fails and stops matching when one of the given rules fails.
* Consumes everything that the rules `R...` consumed.
* Succeeds if `R` is an empty rule pack.
* [Meta data] and [implementation] mapping:
  - `seq<>::rule_t` is `internal::success`
  - `seq< R >::rule_t` is `internal::seq< R >`
  - `seq< R >::subs_t` is `type_list< R >`
  - `seq< R... >::rule_t` is `internal::seq< R... >`
  - `seq< R... >::subs_t` is `type_list< R... >`

###### `sor< R... >`

* PEG **ordered choice** *e*<sub>1</sub> / *e*<sub>2</sub>
* Choice or *disjunction* of rules.
* Matches the given rules `R...` in the given order.
* Succeeds and stops matching when one of the given rules succeeds.
* Consumes whatever the first rule that succeeded consumed.
* Fails if `R` is an empty rule pack.
* [Meta data] and [implementation] mapping:
  - `sor<>::rule_t` is `internal::failure`
  - `sor< R >::rule_t` is `internal::sor< R >`
  - `sor< R >::subs_t` is `type_list< R >`
  - `sor< R... >::rule_t` is `internal::sor< R... >`
  - `sor< R... >::subs_t` is `type_list< R... >`

###### `star< R... >`

* PEG **zero-or-more** *e**
* Matches `seq< R... >` as often as possible and always succeeds.
* `R` must be a non-empty rule pack.
* [Meta data] and [implementation] mapping:
  - `star< R >::rule_t` is `internal::star< R >`
  - `star< R >::subs_t` is `type_list< R >`
  - `star< R... >::rule_t` is `internal::star< internal::seq< R... > >`
  - `star< R... >::subs_t` is `type_list< internal::seq< R... > >`

## Convenience

The PEGTL offers a variety of convenience rules which help writing
concise grammars as well as offering performance benefits over the
equivalent implementation with classical PEG combinators.

These rules are in namespace `tao::pegtl`.

###### `if_must< R, S... >`

* Attempts to match `R` and depending on the result proceeds with either `must< S... >` or `failure`.
* [Equivalent] to `seq< R, must< S... > >`.
* [Equivalent] to `if_then_else< R, must< S... >, failure >`.
* [Meta data] and [implementation] mapping:
  - `if_must< R >::rule_t` is `internal::if_must< false, R >`
  - `if_must< R >::subs_t` is `type_list< R >`
  - `if_must< R, S... >::rule_t` is `internal::if_must< false, R, S... >`
  - `if_must< R, S... >::subs_t` is `type_list< R, internal::must< S... > >`

Note that the `false` template parameter to `internal::if_must` corresponds to the `failure` in the equivalent description using `if_then_else`.

###### `if_must_else< R, S, T >`

* Attempts to match `R` and depending on the result proceeds with either `must< S >` or `must< T >`.
* [Equivalent] to `if_then_else< R, must< S >, must< T > >`.
* [Meta data] and [implementation] mapping:
  - `if_must_else< R, S, T >::rule_t` is `internal::if_then_else< R, internal::must< S >, internal::must< T > >`
  - `if_must_else< R, S, T >::subs_t` is `type_list< R, internal::must< S >, internal::must< T > >`

###### `if_then_else< R, S, T >`

* [Equivalent] to `sor< seq< R, S >, seq< not_at< R >, T > >`.
* [Meta data] and [implementation] mapping:
  - `if_then_else< R, S, T >::rule_t` is `internal::if_then_else< R, S, T>`
  - `if_then_else< R, S, T >::subs_t` is `type_list< R, S, T >`

###### `list< R, S >`

* Matches a non-empty list of `R` separated by `S`.
* [Equivalent] to `seq< R, star< S, R > >`.
* [Meta data] and [implementation] mapping:
  - `list< R, S >::rule_t` is `internal::seq< R, internal::star< S, R > >`
  - `list< R, S >::subs_t` is `type_list< R, internal::star< S, R > >`

###### `list< R, S, P >`

* Matches a non-empty list of `R` separated by `S` where each `S` can be padded by `P`.
* [Equivalent] to `seq< R, star< pad< S, P >, R > >`.
* [Meta data] and [implementation] mapping:
  - `list< R, S, P >::rule_t` is `internal::seq< R, internal::star< internal::pad< S, P >, R > >`
  - `list< R, S, P >::subs_t` is `type_list< R, internal::star< internal::pad< S, P >, R > >`

###### `list_must< R, S >`

* Matches a non-empty list of `R` separated by `S`.
* Similar to `list< R, S >`, but if there is an `S` it **must** be followed by an `R`.
* [Equivalent] to `seq< R, star< if_must< S, R > > >`.
* [Meta data] and [implementation] mapping:
  - `list_must< R, S >::rule_t` is `internal::seq< R, internal::star< S, internal::must< R > > >`
  - `list_must< R, S >::subs_t` is `type_list< R, internal::star< S, internal::must< R > > >`

###### `list_must< R, S, P >`

* Matches a non-empty list of `R` separated by `S` where each `S` can be padded by `P`.
* Similar to `list< R, S, P >`, but if there is an `S` it **must** be followed by an `R`.
* [Equivalent] to `seq< R, star< if_must< pad< S, P >, R > > >`.
* [Meta data] and [implementation] mapping:
  - `list_must< R, S, P >::rule_t` is `internal::seq< R, internal::star< internal::pad< S, P >, internal::must< R > > >`
  - `list_must< R, S, P >::subs_t` is `type_list< R, internal::star< internal::pad< S, P >, internal::must< R > > >`

###### `list_tail< R, S >`

* Matches a non-empty list of `R` separated by `S` with optional trailing `S`.
* [Equivalent] to `seq< list< R, S >, opt< S > >`.
* [Equivalent] to `seq< R, star_partial< S, R > >`.
* [Meta data] and [implementation] mapping:
  - `list_tail< R, S >::rule_t` is `internal::seq< R, internal::star_partial< S, R > >`
  - `list_tail< R, S >::subs_t` is `type_list< R, internal::star_partial< S, R > >`

###### `list_tail< R, S, P >`

* Matches a non-empty list of `R` separated by `S` with optional trailing `S` and padding `P` inside the list.
* [Equivalent] to `seq< list< R, S, P >, opt< star< P >, S > >`.
* [Equivalent] to `seq< R, star_partial< padl< S, P >, padl< R, P > > >`.
* [Meta data] and [implementation] mapping:
  - `list_tail< R, S, P >::rule_t` is `internal::seq< R, internal::star_partial< internal::padl< S, P >, internal::padl< R, P > > >`
  - `list_tail< R, S, P >::subs_t` is `type_list< R, internal::star_partial< internal::padl< S, P >, internal::padl< R, P > > >`

###### `minus< M, S >`

* Succeeds if `M` matches, and `S` does *not* match *all* of the input that `M` matched.
* [Equivalent] to `rematch< M, not_at< S, eof > >`.
* [Meta data] and [implementation] mapping:
  - `minus< M, S >::rule_t` is `internal::rematch< M, internal::not_at< S, internal::eof > >`
  - `minus< M, S >::subs_t` is `type_list< M, internal::not_at< S, internal::eof > >`

###### `must< R... >`

* [Equivalent] to `seq< R... >`, but:
* Converts local failure of `R...` into global failure.
* Calls `raise< R >` for the `R` that failed.
* [Equivalent] to `seq< sor< R, raise< R > >... >`.
* [Meta data] and [implementation] mapping:
  - `must<>::rule_t` is `internal::success`
  - `must< R >::rule_t` is `internal::must< R >`
  - `must< R >::subs_t` is `type_list< R >`
  - `must< R... >::rule_t` is `internal::seq< internal::must< R >... >::rule_t`
  - `must< R... >::subs_t` is `type_list< internal::must< R... > >`

Note that `must` uses a different pattern to handle multiple sub-rules compared to the other `seq`-equivalent rules (which use `rule< seq< R... > >` rather than `seq< rule< R >... >`).

###### `opt_must< R, S... >`

* [Equivalent] to `opt< if_must< R, S... > >`.
* [Equivalent] to `if_then_else< R, must< S... >, success >`.
* [Meta data] and [implementation] mapping:
  - `opt_must< R >::rule_t` is `internal::if_must< true, R >`
  - `opt_must< R >::subs_t` is `type_list< R >`
  - `opt_must< R, S... >::rule_t` is `internal::if_must< true, R, S... >`
  - `opt_must< R, S... >::subs_t` is `type_list< R, internal::must< S... > >`

Note that the `true` template parameter to `internal::if_must` corresponds to the `success` in the equivalent description using `if_then_else`.

###### `pad< R, S, T = S >`

* Matches an `R` that can be padded by arbitrary many `S` on the left and `T` on the right.
* [Equivalent] to `seq< star< S >, R, star< T > >`.
* [Meta data] and [implementation] mapping:
  - `pad< R, S, T >::rule_t` is `internal::seq< internal::star< S >, R, internal::star< T > >`
  - `pad< R, S, T >::subs_t` is `type_list< internal::star< S >, R, internal::star< T > >`

###### `pad_opt< R, P >`

* Matches an optional `R` that can be padded by arbitrary many `P` or just arbitrary many `P`.
* [Equivalent] to `seq< star< P >, opt< R, star< P > > >`.
* [Meta data] and [implementation] mapping:
  - `pad_opt< R, P >::rule_t` is `internal::seq< internal::star< P >, internal::opt< R, internal::star< P > > >`
  - `pad_opt< R, P >::subs_t` is `type_list< internal::star< P >, internal::opt< R, internal::star< P > > >`

###### `partial< R... >`

* Similar to `opt< R... >` with one important difference:
* Does *not* rewind the input after a partial match of `R...`.
* Attempts to match the given rules `R...` in the given order.
* Succeeds and stops matching when one of the given rules fails;
* succeds when all of the given rules succeed.
* Consumes everything that the successful rules of `R...` consumed.
* `R` must be a non-empty rule pack.
* [Equivalent] to `opt< R >` when `R...` is a single rule.
* [Meta data] and [implementation] mapping:
  - `partial< R... >::rule_t` is `internal::partial< R... >`
  - `partial< R... >::subs_t` is `type_list< R... >`

###### `rematch< R, S... >`

* Succeeds if `R` matches, and each `S` matches the input that `R` matched.
* Ignores all `S` for the [grammar analysis](Grammar-Analysis.md).
* [Meta data] and [implementation] mapping:
  - `rematch< R, S... >::rule_t` is `internal::rematch< R, S... >`
  - `rematch< R, S... >::subs_t` is `type_list< R, S... >`

Note that the `S` do *not* need to match *all* of the input matched by `R` (which is why `minus` uses `eof` in its implementation).

###### `rep< Num, R... >`

* Matches `seq< R... >` for `Num` times without checking for further matches.
* [Equivalent] to `seq< seq< R... >, ..., seq< R... > >` where `seq< R... >` is repeated `Num` times.
* [Meta data] and [implementation] mapping:
  - `rep< 0, R... >::rule_t` is `internal::success`
  - `rep< N >::rule_t` is `internal::success`
  - `rep< N, R >::rule_t` is `internal::rep< N, R >`
  - `rep< N, R >::subs_t` is `type_list< R >`
  - `rep< N, R... >::rule_t` is `internal::rep< N, internal::seq< R... > >`
  - `rep< N, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `rep_max< Max, R... >`

* Matches `seq< R... >` for at most `Max` times and verifies that it doesn't match more often.
* [Equivalent] to `rep_min_max< 0, Max, R... >`.
* [Meta data] and [implementation] mapping:
  - `rep_max< 0, R >::rule_t` is `internal::not_at< R >`
  - `rep_max< 0, R >::subs_t` is `type_list< R >`
  - `rep_max< 0, R... >::rule_t` is `internal::not_at< internal::seq< R... > >`
  - `rep_max< 0, R... >::subs_t` is `type_list< internal::seq< R... > >`
  - `rep_max< Max >::rule_t` is `internal::failure`
  - `rep_max< Max, R >::rule_t` is `internal::rep_min_max< 0, Max, R >`
  - `rep_max< Max, R >::subs_t` is `type_list< R >`
  - `rep_max< Max, R... >::rule_t` is `internal::rep_min_max< 0, Max, internal::seq< R... > >`
  - `rep_max< Max, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `rep_min< Min, R... >`

* Matches `seq< R... >` as often as possible and succeeds if it matches at least `Min` times.
* [Equivalent] to `seq< rep< Min, R... >, star< R... > >`.
* `R` must be a non-empty rule pack.
* [Meta data] and [implementation] mapping:
  - `rep_min< Min, R... >::rule_t` is `internal::seq< internal::rep< Min, R... >, internal::star< R... > >`
  - `rep_min< Min, R... >::subs_t` is `type_list< internal::rep< Min, R... >, internal::star< R... > >`

###### `rep_min_max< Min, Max, R... >`

* Matches `seq< R... >` for `Min` to `Max` times and verifies that it doesn't match more often.
* [Equivalent] to `seq< rep< Min, R... >, rep_opt< Max - Min, R... >, not_at< R... > >`.
* [Meta data] and [implementation] mapping:
  - `rep_min_max< 0, 0, R >::rule_t` is `internal::not_at< R >`
  - `rep_min_max< 0, 0, R >::subs_t` is `type_list< R >`
  - `rep_min_max< 0, 0, R... >::rule_t` is `internal::not_at< internal::seq< R... > >`
  - `rep_min_max< 0, 0, R... >::subs_t` is `type_list< internal::seq< R... > >`
  - `rep_min_max< Min, Max >::rule_t` is `internal::failure`
  - `rep_min_max< Min, Max, R >::rule_t` is `internal::rep_min_max< Min, Max, R >`
  - `rep_min_max< Min, Max, R >::subs_t` is `type_list< R >`
  - `rep_min_max< Min, Max, R... >::rule_t` is `internal::rep_min_max< Min, Max, internal::seq< R... > >`
  - `rep_min_max< Min, Max, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `rep_opt< Num, R... >`

* Matches `seq< R... >` for zero to `Num` times without check for further matches.
* [Equivalent] to `rep< Num, opt< R... > >`.
* [Meta data] and [implementation] mapping:
  - `rep_opt< 0, R... >::rule_t` is `internal::success`
  - `rep_opt< Num >::rule_t` is `internal::success`
  - `rep_opt< Num, R... >::rule_t` is `internal::seq< internal::rep< Num, R... >, internal::star< R... > >`
  - `rep_opt< Num, R... >::subs_t` is `type_list< internal::rep< Num, R... >, internal::star< R... > >`

###### `star_must< R, S... >`

* [Equivalent] to `star< if_must< R, S... > >`.
* [Meta data] and [implementation] mapping:
  - `star_must< R >::rule_t` is `internal::star< internal::if_must< false, R > >`
  - `star_must< R >::subs_t` is `type_list< internal::if_must< false, R > >`
  - `star_must< R, S... >::rule_t` is `internal::star< internal::if_must< false, R, S... > >`
  - `star_must< R, S... >::subs_t` is `type_list< internal::if_must< false, R, S... > >`

###### `star_partial< R... >`

* Similar to `star< R... >` with one important difference:
* The final iteration does *not* rewind the input after a partial match of `R...`.
* `R` must be a non-empty rule pack.
* [Meta data] and [implementation] mapping:
  - `star_partial< R... >::rule_t` is `internal::star_partial< R... >`
  - `star_partial< R... >::subs_t` is `type_list< R... >`

###### `star_strict< R... >`

* Similar to `star< R... >` with one important difference:
* A partial match of `R...` lets `star_strict` fail locally.
* `R` must be a non-empty rule pack.
* [Meta data] and [implementation] mapping:
  - `star_strict< R... >::rule_t` is `internal::star_strict< R... >`
  - `star_strict< R... >::subs_t` is `type_list< R... >`

###### `strict< R... >`

* Similar to `opt< R... >` with one important difference:
* A partial match of `R...` lets `strict` fail locally.
* [Equivalent] to `sor< not_at< R1 >, seq< R... > >` if `R1` is the first rule of `R...`.
* `R` must be a non-empty rule pack.
* [Meta data] and [implementation] mapping:
  - `strict< R... >::rule_t` is `internal::strict< R... >`
  - `strict< R... >::subs_t` is `type_list< R... >`

###### `try_catch_any_raise_nested< R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of any type via `catch( ... )` and:
* Throws a new exception with the caught one as nested exception.
* Throws via `Control< R >::raise_nested()` when `R...` is a single rule.
* Throws via `Control< internal::seq< R... > >::raise_nested()` when `R...` is more than one rule.
* [Meta data] and [implementation] mapping:
  - `try_catch_any_raise_nested<>::rule_t` is `internal::success`
  - `try_catch_any_raise_nested< R >::rule_t` is `internal::try_catch_raise_nested< void, R >`
  - `try_catch_any_raise_nested< R >::subs_t` is `type_list< R >`
  - `try_catch_any_raise_nested< R... >::rule_t` is `internal::try_catch_raise_nested< void, internal::seq< R... > >`
  - `try_catch_any_raise_nested< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_any_return_false< E, R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of any type via `catch( ... )`, and:
* Converts the global failure (exception) into a local failure (return value `false`).
* [Meta data] and [implementation] mapping:
  - `try_catch_any_return_false< E >::rule_t` is `internal::success`
  - `try_catch_any_return_false< E, R >::rule_t` is `internal::try_catch_return_false< void, R >`
  - `try_catch_any_return_false< E, R >::subs_t` is `type_list< R >`
  - `try_catch_any_return_false< E, R... >::rule_t` is `internal::try_catch_return_false< void, internal::seq< R... > >`
  - `try_catch_any_return_false< E, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_raise_nested< R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of type `tao::pegtl::parse_error_base` (or derived), and:
* Throws a new exception with the caught one as nested exception.
* Throws via `Control< R >::raise_nested()` when `R...` is a single rule.
* Throws via `Control< internal::seq< R... > >::raise_nested()` when `R...` is more than one rule.
* [Meta data] and [implementation] mapping:
  - `try_catch_raise_nested<>::rule_t` is `internal::success`
  - `try_catch_raise_nested< R >::rule_t` is `internal::try_catch_raise_nested< parse_error_base, R >`
  - `try_catch_raise_nested< R >::subs_t` is `type_list< R >`
  - `try_catch_raise_nested< R... >::rule_t` is `internal::try_catch_raise_nested< parse_error_base, internal::seq< R... > >`
  - `try_catch_raise_nested< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_return_false< R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of type `tao::pegtl::parse_error_base` (or derived), and:
* Converts the global failure (exception) into a local failure (return value `false`).
* [Meta data] and [implementation] mapping:
  - `try_catch_return_false<>::rule_t` is `internal::success`
  - `try_catch_return_false< R >::rule_t` is `internal::try_catch_return_false< parse_error_base, R >`
  - `try_catch_return_false< R >::subs_t` is `type_list< R >`
  - `try_catch_return_false< R... >::rule_t` is `internal::try_catch_return_false< parse_error_base, internal::seq< R... > >`
  - `try_catch_return_false< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_std_raise_nested< R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of type `std::exception` (or derived), and:
* Throws a new exception with the caught one as nested exception.
* Throws via `Control< R >::raise_nested()` when `R...` is a single rule.
* Throws via `Control< internal::seq< R... > >::raise_nested()` when `R...` is more than one rule.
* [Meta data] and [implementation] mapping:
  - `try_catch_std_raise_nested<>::rule_t` is `internal::success`
  - `try_catch_std_raise_nested< R >::rule_t` is `internal::try_catch_raise_nested< std::exception, R >`
  - `try_catch_std_raise_nested< R >::subs_t` is `type_list< R >`
  - `try_catch_std_raise_nested< R... >::rule_t` is `internal::try_catch_raise_nested< std::exception, internal::seq< R... > >`
  - `try_catch_std_raise_nested< R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_std_return_false< E, R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of type `std::exception` (or derived), and:
* Converts the global failure (exception) into a local failure (return value `false`).
* [Meta data] and [implementation] mapping:
  - `try_catch_std_return_false< E >::rule_t` is `internal::success`
  - `try_catch_std_return_false< E, R >::rule_t` is `internal::try_catch_return_false< std::exception, R >`
  - `try_catch_std_return_false< E, R >::subs_t` is `type_list< R >`
  - `try_catch_std_return_false< E, R... >::rule_t` is `internal::try_catch_return_false< std::exception, internal::seq< R... > >`
  - `try_catch_std_return_false< E, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_type_raise_nested< E, R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of type `E` (or derived), and:
* Throws a new exception with the caught one as nested exception.
* Throws via `Control< R >::raise_nested()` when `R...` is a single rule.
* Throws via `Control< internal::seq< R... > >::raise_nested()` when `R...` is more than one rule.
* [Meta data] and [implementation] mapping:
  - `try_catch_type_raise_nested< E >::rule_t` is `internal::success`
  - `try_catch_type_raise_nested< E, R >::rule_t` is `internal::try_catch_raise_nested< E, R >`
  - `try_catch_type_raise_nested< E, R >::subs_t` is `type_list< R >`
  - `try_catch_type_raise_nested< E, R... >::rule_t` is `internal::try_catch_raise_nested< E, internal::seq< R... > >`
  - `try_catch_type_raise_nested< E, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `try_catch_type_return_false< E, R... >`

* [Equivalent] to `seq< R... >`, but:
* Catches exceptions of type `E` (or derived), and:
* Converts the global failure (exception) into a local failure (return value `false`).
* [Meta data] and [implementation] mapping:
  - `try_catch_type_return_false< E >::rule_t` is `internal::success`
  - `try_catch_type_return_false< E, R >::rule_t` is `internal::try_catch_return_false< E, R >`
  - `try_catch_type_return_false< E, R >::subs_t` is `type_list< R >`
  - `try_catch_type_return_false< E, R... >::rule_t` is `internal::try_catch_return_false< E, internal::seq< R... > >`
  - `try_catch_type_return_false< E, R... >::subs_t` is `type_list< internal::seq< R... > >`

###### `until< R >`

* Consumes all input until `R` matches.
* [Equivalent] to `until< R, any >`.
* [Meta data] and [implementation] mapping:
  - `until< R >::rule_t` is `internal::until< R >`
  - `until< R >::subs_t` is `type_list< R >`

###### `until< R, S... >`

* Matches `seq< S... >` as long as `at< R >` does not match and succeeds when `R` matches.
* [Equivalent] to `seq< star< not_at< R >, S... >, R >`.
* Does not apply if `S` is an empty rule pack, see the previous entry for the semantics of `until< R >`.
* [Meta data] and [implementation] mapping:
  - `until< R, S >::rule_t` is `internal::until< R, S >`
  - `until< R, S >::subs_t` is `type_list< R, S >`
  - `until< R, S... >::rule_t` is `internal::until< R, internal::seq< S... > >`
  - `until< R, S... >::subs_t` is `type_list< R, internal::seq< S... > >`

## Action Rules

These rules are in namespace `tao::pegtl`.

These rules replicate the intrusive way actions were called from within the grammar in the PEGTL 0.x with the `apply<>` and `if_apply<>` rules.
The actions for these rules are classes (rather than class templates as required for `parse()` and the `action<>`-rule).
These rules respect the current `apply_mode`, but do **not** use the control class to invoke the actions.

###### `apply< A... >`

* Calls `A::apply()` for all `A`, in order, with an empty input and all states as arguments.
* If any `A::apply()` has a boolean return type and returns `false`, no further `A::apply()` calls are made and the result is equivalent to `failure`, otherwise:
* [Equivalent] to `success` wrt. parsing.
* [Meta data] and [implementation] mapping:
  - `apply< A... >::rule_t` is `internal::apply< A... >`

###### `apply0< A... >`

* Calls `A::apply0()` for all `A`, in order, with all states as arguments.
* If any `A::apply0()` has a boolean return type and returns `false`, no further `A::apply0()` calls are made and the result is equivalent to `failure`, otherwise:
* [Equivalent] to `success` wrt. parsing.
* [Meta data] and [implementation] mapping:
  - `apply0< A... >::rule_t` is `internal::apply0< A... >`

###### `if_apply< R, A... >`

* [Equivalent] to `seq< R, apply< A... > >` wrt. parsing, but also:
* If `R` matches, calls `A::apply()`, for all `A`, in order, with the input matched by `R` and all states as arguments.
* If any `A::apply()` has a boolean return type and returns `false`, no further `A::apply()` calls are made.
* [Meta data] and [implementation] mapping:
  - `if_apply< R, A... >::rule_t` is `internal::if_apply< R, A... >`
  - `if_apply< R, A... >::subs_t` is `type_list< R >`

## Atomic Rules

These rules are in namespace `tao::pegtl`.

Atomic rules do not rely on other rules.

###### `bof`

* Succeeds at "beginning-of-file", i.e. when the input's `byte()` member function returns zero.
* Does not consume input.
* Does **not** work with inputs that don't have a `byte()` member function.
* [Meta data] and [implementation] mapping:
  - `bof::rule_t` is `internal::bof`

###### `bol`

* Succeeds at "beginning-of-line", i.e. when the input's `column()` member function returns one.
* Does not consume input.
* Does **not** work with inputs that don't have a `column()` member function.
* [Meta data] and [implementation] mapping:
  - `bol::rule_t` is `internal::bol`

###### `bytes< Num >`

* Succeeds when the input contains at least `Num` further bytes.
* Consumes these `Num` bytes from the input.
* [Meta data] and [implementation] mapping:
  - `bytes< 0 >::rule_t` is `internal::success`
  - `bytes< Num >::rule_t` is `internal::bytes< Num >`

###### `eof`

* Succeeds at "end-of-file", i.e. when the input is empty or all input has been consumed.
* Does not consume input.
* [Meta data] and [implementation] mapping:
  - `eof::rule_t` is `internal::eof`

###### `eol`

* Depends on the `Eol` template parameter of the input, by default:
* Matches and consumes a Unix or MS-DOS line ending, that is:
* [Equivalent] to `sor< one< '\n' >, string< '\r', '\n' > >`.
* [Meta data] and [implementation] mapping:
  - `eol::rule_t` is `internal::eol`

###### `eolf`

* [Equivalent] to `sor< eof, eol >`.
* [Meta data] and [implementation] mapping:
  - `eolf::rule_t` is `internal::eolf`

###### `everything`

* Matches and consumes the entire input in one go, but:
* Limited by the buffer size when using an [Incremental Input].
* [Equivalent] to `until< eof, any >`.
* [Meta data] and [implementation] mapping:
  - `everything::rule_t` is `internal::everything< std::size_t >`

###### `failure`

* Dummy rule that never succeeds.
* Does not consume input.
* [Meta data] and [implementation] mapping:
  - `failure::rule_t` is `internal::failure`

###### `raise< T >`

* Generates a *global failure*.
* Calls the control-class' `Control< T >::raise()` static member function.
* `T` *can* be a rule, but it does not have to be a rule.
* Does not consume input.
* [Meta data] and [implementation] mapping:
  - `raise< T >::rule_t` is `internal::raise< T >`

###### `raise_message< C... >`

* Generates a *global failure* with the message given by `C...`.
* Calls the control-class' `Control< raise_message< C... > >::raise()` static member function.
* Does not consume input.
* [Meta data] and [implementation] mapping:
  - `raise_message< C... >::rule_t` is `internal::raise< raise_message< C... > >`

###### `success`

* Dummy rule that always succeeds.
* Does not consume input.
* [Meta data] and [implementation] mapping:
  - `success::rule_t` is `internal::success`

###### `TAO_PEGTL_RAISE_MESSAGE( "..." )`

* Macro where `TAO_PEGTL_RAISE_MESSAGE( "foo" )` yields `raise_message< 'f', 'o', 'o' >`.
* The argument must be a string literal.
* Works for strings up to 512 bytes of length (excluding trailing `'\0'`).

## ASCII Rules

These rules are in the inline namespace `tao::pegtl::ascii`.

The ASCII rules operate on single bytes, without restricting the range of values to 7 bits.
They are compatible with input with the 8th bit set in the sense that nothing breaks in their presence.
Rules like `ascii::any` or `ascii::not_one< 'a' >` will match all possible byte values,
and all possible byte values excluding `'a'`, respectively. However the character class rules like
`ascii::alpha` only match the corresponding ASCII characters.

(It is possible to match UTF-8 multi-byte characters with the ASCII rules,
for example the Euro sign code point `U+20AC`, which is encoded by the UTF-8 sequence `E2 82 AC`,
can be matched by either `tao::pegtl::ascii::string< 0xe2, 0x82, 0xac >` or `tao::pegtl::utf8::one< 0x20ac >`.)

ASCII rules do not usually rely on other rules.

###### `alnum`

* Matches and consumes a single ASCII alphabetic or numeric character.
* [Equivalent] to `ranges< 'a', 'z', 'A', 'Z', '0', '9' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::alnum::rule_t` is `internal::ranges< internal::peek_char, 'a', 'z', 'A', 'Z', '0', '9' >`

###### `alpha`

* Matches and consumes a single ASCII alphabetic character.
* [Equivalent] to `ranges< 'a', 'z', 'A', 'Z' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::alpha::rule_t` is `internal::ranges< internal::peek_char, 'a', 'z', 'A', 'Z' >`

###### `any`

* Matches and consumes any single byte, including all ASCII characters.
* [Equivalent] to `bytes< 1 >`.
* [Meta data] and [implementation] mapping:
  - `ascii::any::rule_t` is `internal::any< internal::peek_char >`

###### `blank`

* Matches and consumes a single ASCII horizontal space or horizontal tabulator character.
* [Equivalent] to `one< ' ', '\t' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::blank::rule_t` is `internal::one< internal::result_on_found::success, internal::peek_char, ' ', '\t' >`

###### `digit`

* Matches and consumes a single ASCII decimal digit character.
* [Equivalent] to `range< '0', '9' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::digit::rule_t` is `internal::range< internal::result_on_found::success, internal::peek_char, '0', '9' >`

###### `ellipsis`

* Matches and consumes three dots.
* [Equivalent] to `three< '.' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::ellipsis::rule_t` is `internal::string< '.', '.', '.' >`

###### `forty_two< C... >`

* [Equivalent] to `rep< 42, one< C... > >`.
* [Meta data] and [implementation] mapping:
  - `ascii::forty_two< C >::rule_t` is `internal_rep< 42, internal::one< internal::result_on_found::success, internal::peek_char, C > >`

###### `identifier_first`

* Matches and consumes a single ASCII character permissible as first character of a C identifier.
* [Equivalent] to `ranges< 'a', 'z', 'A', 'Z', '_' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::identifier_first::rule_t` is `internal::ranges< internal::peek_char, 'a', 'z', 'A', 'Z', '_' >`

###### `identifier_other`

* Matches and consumes a single ASCII character permissible as subsequent character of a C identifier.
* [Equivalent] to `ranges< 'a', 'z', 'A', 'Z', '0', '9', '_' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::identifier_first::rule_t` is `internal::ranges< internal::peek_char, 'a', 'z', 'A', 'Z', '0', '9', '_' >`

###### `identifier`

* Matches and consumes an ASCII identifier as defined for the C programming language.
* [Equivalent] to `seq< identifier_first, star< identifier_other > >`.
* [Meta data] and [implementation] mapping:
  - `ascii::identifier::rule_t` is `internal::seq< identifier_first, internal::star< identifier_other > >`.

###### `istring< C... >`

* Matches and consumes the given ASCII string `C...` with case insensitive matching.
* Similar to `string< C... >`, but:
* For ASCII letters a-z and A-Z the match is case insensitive.
* [Meta data] and [implementation] mapping:
  - `ascii::istring<>::rule_t` is `internal::success`
  - `ascii::istring< C... >::rule_t` is `internal::istring< C... >`

###### `keyword< C... >`

* Matches and consumes a non-empty string not followed by an identifier character.
* [Equivalent] to `seq< string< C... >, not_at< identifier_other > >`.
* `C` must be a non-empty character pack.
* [Meta data] and [implementation] mapping:
  - `ascii::keyword< C... >::rule_t` is `internal::seq< internal::string< C... >, internal::not_at< internal::ranges< internal::peek_char, 'a', 'z', 'A', 'Z', '0', '9', '_' > > >`

###### `lower`

* Matches and consumes a single ASCII lower-case alphabetic character.
* [Equivalent] to `range< 'a', 'z' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::lower::rule_t` is `internal::range< internal::result_on_found::success, internal::peek_char, 'a', 'z' >`

###### `not_one< C... >`

* Succeeds when the input is not empty, and:
* `C` is an empty character pack or the next input byte is **not** one of `C...`.
* Consumes one byte when it succeeds.
* [Meta data] and [implementation] mapping:
  - `ascii::not_one<>::rule_t` is `internal::any< internal::peek_char >`
  - `ascii::not_one< C... >::rule_t` is `internal::one< result_on_found::failure, internal::peek_char, C... >`

###### `not_range< C, D >`

* Succeeds when the input is not empty, and:
* The next input byte is **not** in the closed range `C ... D`.
* Consumes one byte when it succeeds.
* [Meta data] and [implementation] mapping:
  - `ascii::not_range< C, C >::rule_t` is `internal::one< result_on_found::failure, internal::peek_char, C >`
  - `ascii::not_range< C, D >::rule_t` is `internal::range< result_on_found::failure, internal::peek_char, C, D >`

###### `nul`

* Matches and consumes an ASCII nul character.
* [Equivalent] to `one< '\0' >`.
  - `ascii::nul::rule_t` is `internal::one< result_on_found::success, internal::peek_char, 0 >`

###### `odigit`

* Matches and consumes a single ASCII octal digit character.
* [Equivalent] to `range< '0', '7' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::digit::rule_t` is `internal::range< internal::result_on_found::success, internal::peek_char, '0', '7' >`

###### `one< C... >`

* Succeeds when the input is not empty, and:
* The next input byte is one of `C...`.
* Consumes one byte when it succeeds.
* Fails if `C` is an empty character pack.
* [Meta data] and [implementation] mapping:
  - `ascii::not_one<>::rule_t` is `internal::failure`
  - `ascii::not_one< C... >::rule_t` is `internal::one< result_on_found::success, internal::peek_char, C... >`

###### `print`

* Matches and consumes any single ASCII character traditionally defined as printable.
* [Equivalent] to `range< 32, 126 >`.
* [Meta data] and [implementation] mapping:
  - `ascii::print::rule_t` is `internal::range< internal::result_on_found::success, internal::peek_char, 32, 126 >`

###### `range< C, D >`

* Succeeds when the input is not empty, and:
* The next input byte is in the closed range `C ... D`.
* Consumes one byte when it succeeds.
* [Meta data] and [implementation] mapping:
  - `ascii::range< C, C >::rule_t` is `internal::one< result_on_found::success, internal::peek_char, C >`
  - `ascii::range< C, D >::rule_t` is `internal::range< result_on_found::success, internal::peek_char, C, D >`

###### `ranges< C1, D1, C2, D2, ... >`
###### `ranges< C1, D1, C2, D2, ..., E >`

* [Equivalent] to `sor< range< C1, D1 >, range< C2, D2 >, ... >`.
* [Equivalent] to `sor< range< C1, D1 >, range< C2, D2 >, ..., one< E > >`.
* [Meta data] and [implementation] mapping:
  - `ascii::ranges<>::rule_t` is `internal::failure`
  - `ascii::ranges< E >::rule_t` is `internal::one< result_on_found::success, internal::peek_char, E >`
  - `ascii::ranges< C, D >::rule_t` is `internal::range< result_on_found::success, internal::peek_char, C, D >`
  - `ascii::ranges< C... >::rule_t` is `internal::ranges< internal::peek_char, C... >`

###### `seven`

* Matches and consumes any single true ASCII character that fits into 7 bits.
* [Equivalent] to `range< 0, 127 >`.
* [Meta data] and [implementation] mapping:
  - `ascii::seven::rule_t` is `internal::range< internal::result_on_found::success, internal::peek_char, 0, 127 >`

###### `shebang`

* [Equivalent] to `if_must< string< '#', '!' >, until< eolf > >`.
* [Meta data] and [implementation] mapping:
  - `ascii::shebang::rule_t` is `internal::seq< false, internal::string< '#', '!' >, internal::until< internal::eolf > >`
  - `ascii::shebang::subs_t` is `type_list< internal::string< '#', '!' >, internal::until< internal::eolf > >`

###### `space`

* Matches and consumes a single space, line-feed, carriage-return, horizontal-tab, vertical-tab or form-feed.
* [Equivalent] to `one< ' ', '\n', '\r', '\t', '\v', '\f' >`.

###### `string< C... >`

* Matches and consumes a string, a sequence of bytes or single-byte characters.
* [Equivalent] to `seq< one< C >... >`.
* [Meta data] and [implementation] mapping:
  - `ascii::string<>::rule_t` is `internal::success`
  - `ascii::string< C... >::rule_t` is `internal::string< C... >`

###### `TAO_PEGTL_ISTRING( "..." )`

* Macro where `TAO_PEGTL_ISTRING( "foo" )` yields `istring< 'f', 'o', 'o' >`.
* The argument must be a string literal.
* Works for strings up to 512 bytes of length (excluding trailing `'\0'`).
* Strings may contain embedded `'\0'`.

###### `TAO_PEGTL_KEYWORD( "..." )`

* Macro where `TAO_PEGTL_KEYWORD( "foo" )` yields `keyword< 'f', 'o', 'o' >`.
* The argument must be a string literal.
* Works for keywords up to 512 bytes of length (excluding trailing `'\0'`).
* Strings may contain embedded `'\0'`.

###### `TAO_PEGTL_STRING( "..." )`

* Macro where `TAO_PEGTL_STRING( "foo" )` yields `string< 'f', 'o', 'o' >`.
* The argument must be a string literal.
* Works for strings up to 512 bytes of length (excluding trailing `'\0'`).
* Strings may contain embedded `'\0'`.

###### `three< C >`

* Succeeds when the input contains at least three bytes, and:
* These three input bytes are all `C`.
* Consumes three bytes when it succeeds.
* [Meta data] and [implementation] mapping:
  - `ascii::three< C >::rule_t` is `internal::string< C, C, C >`

###### `two< C >`

* Succeeds when the input contains at least two bytes, and:
* These two input bytes are both `C`.
* Consumes two bytes when it succeeds.
* [Meta data] and [implementation] mapping:
  - `ascii::two< C >::rule_t` is `internal::string< C, C >`

###### `upper`

* Matches and consumes a single ASCII upper-case alphabetic character.
* [Equivalent] to `range< 'A', 'Z' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::upper::rule_t` is `internal::range< internal::result_on_found::success, internal::peek_char, 'A', 'Z' >`

###### `xdigit`

* Matches and consumes a single ASCII hexadecimal digit character.
* [Equivalent] to `ranges< '0', '9', 'a', 'f', 'A', 'F' >`.
* [Meta data] and [implementation] mapping:
  - `ascii::xdigit::rule_t` is `internal::ranges< internal::peek_char, '0', '9', 'a', 'f', 'A', 'F' >`

## Unicode Rules

These rules are available in multiple versions,

* in namespace `tao::pegtl::utf8` for UTF-8 encoded inputs,
* in namespace `tao::pegtl::utf16_be` for big-endian UTF-16 encoded inputs,
* in namespace `tao::pegtl::utf16_le` for little-endian UTF-16 encoded inputs,
* in namespace `tao::pegtl::utf32_be` for big-endian UTF-32 encoded inputs,
* in namespace `tao::pegtl::utf32_le` for little-endian UTF-32 encoded inputs.

For convenience, they also appear in multiple namespace aliases,

* namespace alias `tao::pegtl::utf16` for native-endian UTF-16 encoded inputs,
* namespace alias `tao::pegtl::utf32` for native-endian UTF-32 encoded inputs.

The following limitations apply to the UTF-16 and UTF-32 rules:

* Unaligned input leads to unaligned memory access.
* The line and column numbers are not counted correctly.
* They are not automatically included with `tao/pegtl.hpp`.

The UTF-8 rules are included with `include/tao/pegtl.hpp` while the UTF-16 and UTF-32 rules require manual inclusion of the following files.
* `tao/pegtl/contrib/utf16.hpp`
* `tao/pegtl/contrib/utf32.hpp`

While unaligned accesses are no problem on x86 compatible processors, on other architectures they might be very slow or even crash the application.

In the following descriptions a Unicode code point is considered *valid* when it is in the range `0` to `0x10ffff`.
The parameter N stands for the size of the encoding of the next Unicode code point in the input, i.e.

* for UTF-8 the rules are multi-byte-sequence-aware and N is either 1, 2, 3 or 4,
* for UTF-16 the rules are surrogate-pair-aware and N is either 2 or 4, and
* for UTF-32 everything is simple and N is always 4.

It is an error when a code unit in the range `0xd800` to `0xdfff` is encountered outside of a valid UTF-16 surrogate pair (this changed in version 2.6.0).

Unicode rules do not rely on other rules.

###### `any`

* Succeeds when the input is not empty, and:
* The next N bytes encode a valid Unicode code point.
* Consumes the N bytes when it succeeds.

###### `bom`

* [Equivalent] to `one< 0xfeff >`.

###### `not_one< C... >`

* Succeeds when the input is not empty, and:
* The next N bytes encode a valid Unicode code point, and:
* `C` is an empty character pack or the input code point is **not** one of the given code points `C...`.
* Consumes the N bytes when it succeeds.

###### `not_range< C, D >`

* Succeeds when the input is not empty, and:
* The next N bytes encode a valid Unicode code point, and:
* The input code point `B` satisfies `B < C || D < B`.
* Consumes the N bytes when it succeeds.

###### `one< C... >`

* Succeeds when the input is not empty, and:
* The next N bytes encode a valid Unicode code point, and:
* `C` is a non-empty character pack and the input code point is one of the given code points `C...`.
* Consumes the N bytes when it succeeds.

###### `range< C, D >`

* Succeeds when the input is not empty, and:
* The next N bytes encode a valid Unicode code point, and:
* The input code point `B` satisfies `C <= B && B <= D`.
* Consumes the N bytes when it succeeds.

###### `ranges< C1, D1, C2, D2, ... >`

* [Equivalent] to `sor< range< C1, D1 >, range< C2, D2 >, ... >`.

###### `ranges< C1, D1, C2, D2, ..., E >`

* [Equivalent] to `sor< range< C1, D1 >, range< C2, D2 >, ..., one< E > >`.

###### `string< C... >`

* [Equivalent] to `seq< one< C >... >`.

### ICU Support

The following rules depend on the [International Components for Unicode (ICU)](http://icu-project.org/) that provide the means to match characters with specific Unicode character properties.
Because of this external dependency the rules are not automatically included in `tao/pegtl.hpp`.

The ICU-based rules are again available in multiple versions,

* in namespace `tao::pegtl::utf8::icu` for UTF-8 encoded inputs,
* in namespace `tao::pegtl::utf16_be::icu` for big-endian UTF-16 encoded inputs,
* in namespace `tao::pegtl::utf16_le::icu` for little-endian UTF-16 encoded inputs,
* in namespace `tao::pegtl::utf32_be::icu` for big-endian UTF-32 encoded inputs, and
* in namespace `tao::pegtl::utf32_le::icu` for little-endian UTF-32 encoded inputs.

And, for convenience, they again appear in multiple namespace aliases,

* namespace alias `tao::pegtl::utf16::icu` for native-endian UTF-16 encoded inputs,
* namespace alias `tao::pegtl::utf32::icu` for native-endian UTF-32 encoded inputs.

To use these rules it is necessary to provide an include path to the ICU library, to link the application against `libicu`, and to manually include one or more of the following header files:

* `tao/pegtl/contrib/icu/utf8.hpp`
* `tao/pegtl/contrib/icu/utf16.hpp`
* `tao/pegtl/contrib/icu/utf32.hpp`

The convenience ICU rules are supplied for all properties found in ICU version 3.4.
Users of later versions can use the basic rules manually or create their own convenience rules derived from the basic rules for additional enumeration values found in those later versions of the ICU library.

### Basic ICU Rules

Each of the above namespaces provides two basic rules for matching binary properties and property value matching for enum properties.

###### `binary_property< P, V >`

* `P` is a binary property defined by ICU, see [`UProperty`](http://icu-project.org/apiref/icu4c/uchar_8h.html).
* `V` is a boolean value.
* Succeeds when the input is not empty, and:
* The next N bytes encode a valid unicode code point, and:
* The code point's property `P`, i.e. [`u_hasBinaryProperty( cp, P )`](http://icu-project.org/apiref/icu4c/uchar_8h.html), equals `V`.
* Consumes the N bytes when it succeeds.

###### `binary_property< P >`

* Identical to `binary_property< P, true >`.

###### `property_value< P, V >`

* `P` is an enumerated property defined by ICU, see [`UProperty`](http://icu-project.org/apiref/icu4c/uchar_8h.html).
* `V` is an integer value.
* Succeeds when the input is not empty, and:
* The next N bytes encode a valid unicode code point, and:
* The code point's property `P`, i.e. [`u_getIntPropertyValue( cp, P )`](http://icu-project.org/apiref/icu4c/uchar_8h.html), equals `V`.
* Consumes the N bytes when it succeeds.

### ICU Rules for Binary Properties

Convenience wrappers for binary properties.

###### `alphabetic`

* [Equivalent] to `binary_property< UCHAR_ALPHABETIC >`.

###### `ascii_hex_digit`

* [Equivalent] to `binary_property< UCHAR_ASCII_HEX_DIGIT >`.

###### `bidi_control`

* [Equivalent] to `binary_property< UCHAR_BIDI_CONTROL >`.

###### `bidi_mirrored`

* [Equivalent] to `binary_property< UCHAR_BIDI_MIRRORED >`.

###### `case_sensitive`

* [Equivalent] to `binary_property< UCHAR_CASE_SENSITIVE >`.

###### `dash`

* [Equivalent] to `binary_property< UCHAR_DASH >`.

###### `default_ignorable_code_point`

* [Equivalent] to `binary_property< UCHAR_DEFAULT_IGNORABLE_CODE_POINT >`.

###### `deprecated`

* [Equivalent] to `binary_property< UCHAR_DEPRECATED >`.

###### `diacritic`

* [Equivalent] to `binary_property< UCHAR_DIACRITIC >`.

###### `extender`

* [Equivalent] to `binary_property< UCHAR_EXTENDER >`.

###### `full_composition_exclusion`

* [Equivalent] to `binary_property< UCHAR_FULL_COMPOSITION_EXCLUSION >`.

###### `grapheme_base`

* [Equivalent] to `binary_property< UCHAR_GRAPHEME_BASE >`.

###### `grapheme_extend`

* [Equivalent] to `binary_property< UCHAR_GRAPHEME_EXTEND >`.

###### `grapheme_link`

* [Equivalent] to `binary_property< UCHAR_GRAPHEME_LINK >`.

###### `hex_digit`

* [Equivalent] to `binary_property< UCHAR_HEX_DIGIT >`.

###### `hyphen`

* [Equivalent] to `binary_property< UCHAR_HYPHEN >`.

###### `id_continue`

* [Equivalent] to `binary_property< UCHAR_ID_CONTINUE >`.

###### `id_start`

* [Equivalent] to `binary_property< UCHAR_ID_START >`.

###### `ideographic`

* [Equivalent] to `binary_property< UCHAR_IDEOGRAPHIC >`.

###### `ids_binary_operator`

* [Equivalent] to `binary_property< UCHAR_IDS_BINARY_OPERATOR >`.

###### `ids_trinary_operator`

* [Equivalent] to `binary_property< UCHAR_IDS_TRINARY_OPERATOR >`.

###### `join_control`

* [Equivalent] to `binary_property< UCHAR_JOIN_CONTROL >`.

###### `logical_order_exception`

* [Equivalent] to `binary_property< UCHAR_LOGICAL_ORDER_EXCEPTION >`.

###### `lowercase`

* [Equivalent] to `binary_property< UCHAR_LOWERCASE >`.

###### `math`

* [Equivalent] to `binary_property< UCHAR_MATH >`.

###### `nfc_inert`

* [Equivalent] to `binary_property< UCHAR_NFC_INERT >`.

###### `nfd_inert`

* [Equivalent] to `binary_property< UCHAR_NFD_INERT >`.

###### `nfkc_inert`

* [Equivalent] to `binary_property< UCHAR_NFKC_INERT >`.

###### `nfkd_inert`

* [Equivalent] to `binary_property< UCHAR_NFKD_INERT >`.

###### `noncharacter_code_point`

* [Equivalent] to `binary_property< UCHAR_NONCHARACTER_CODE_POINT >`.

###### `pattern_syntax`

* [Equivalent] to `binary_property< UCHAR_PATTERN_SYNTAX >`.

###### `pattern_white_space`

* [Equivalent] to `binary_property< UCHAR_PATTERN_WHITE_SPACE >`.

###### `posix_alnum`

* [Equivalent] to `binary_property< UCHAR_POSIX_ALNUM >`.

###### `posix_blank`

* [Equivalent] to `binary_property< UCHAR_POSIX_BLANK >`.

###### `posix_graph`

* [Equivalent] to `binary_property< UCHAR_POSIX_GRAPH >`.

###### `posix_print`

* [Equivalent] to `binary_property< UCHAR_POSIX_PRINT >`.

###### `posix_xdigit`

* [Equivalent] to `binary_property< UCHAR_POSIX_XDIGIT >`.

###### `quotation_mark`

* [Equivalent] to `binary_property< UCHAR_QUOTATION_MARK >`.

###### `radical`

* [Equivalent] to `binary_property< UCHAR_RADICAL >`.

###### `s_term`

* [Equivalent] to `binary_property< UCHAR_S_TERM >`.

###### `segment_starter`

* [Equivalent] to `binary_property< UCHAR_SEGMENT_STARTER >`.

###### `soft_dotted`

* [Equivalent] to `binary_property< UCHAR_SOFT_DOTTED >`.

###### `terminal_punctuation`

* [Equivalent] to `binary_property< UCHAR_TERMINAL_PUNCTUATION >`.

###### `unified_ideograph`

* [Equivalent] to `binary_property< UCHAR_UNIFIED_IDEOGRAPH >`.

###### `uppercase`

* [Equivalent] to `binary_property< UCHAR_UPPERCASE >`.

###### `variation_selector`

* [Equivalent] to `binary_property< UCHAR_VARIATION_SELECTOR >`.

###### `white_space`

* [Equivalent] to `binary_property< UCHAR_WHITE_SPACE >`.

###### `xid_continue`

* [Equivalent] to `binary_property< UCHAR_XID_CONTINUE >`.

###### `xid_start`

* [Equivalent] to `binary_property< UCHAR_XID_START >`.

### ICU Rules for Enumerated Properties

Convenience wrappers for enumerated properties.

###### `bidi_class< V >`

* `V` is of type `UCharDirection`.
* [Equivalent] to `property_value< UCHAR_BIDI_CLASS, V >`.

###### `block< V >`

* `V` is of type `UBlockCode`.
* [Equivalent] to `property_value< UCHAR_BLOCK, V >`.

###### `decomposition_type< V >`

* `V` is of type `UDecompositionType`.
* [Equivalent] to `property_value< UCHAR_DECOMPOSITION_TYPE, V >`.

###### `east_asian_width< V >`

* `V` is of type `UEastAsianWidth`.
* [Equivalent] to `property_value< UCHAR_EAST_ASIAN_WIDTH, V >`.

###### `general_category< V >`

* `V` is of type `UCharCategory`.
* [Equivalent] to `property_value< UCHAR_GENERAL_CATEGORY, V >`.

###### `grapheme_cluster_break< V >`

* `V` is of type `UGraphemeClusterBreak`.
* [Equivalent] to `property_value< UCHAR_GRAPHEME_CLUSTER_BREAK, V >`.

###### `hangul_syllable_type< V >`

* `V` is of type `UHangulSyllableType`.
* [Equivalent] to `property_value< UCHAR_HANGUL_SYLLABLE_TYPE, V >`.

###### `joining_group< V >`

* `V` is of type `UJoiningGroup`.
* [Equivalent] to `property_value< UCHAR_JOINING_GROUP, V >`.

###### `joining_type< V >`

* `V` is of type `UJoiningType`.
* [Equivalent] to `property_value< UCHAR_JOINING_TYPE, V >`.

###### `line_break< V >`

* `V` is of type `ULineBreak`.
* [Equivalent] to `property_value< UCHAR_LINE_BREAK, V >`.

###### `numeric_type< V >`

* `V` is of type `UNumericType`.
* [Equivalent] to `property_value< UCHAR_NUMERIC_TYPE, V >`.

###### `sentence_break< V >`

* `V` is of type `USentenceBreak`.
* [Equivalent] to `property_value< UCHAR_SENTENCE_BREAK, V >`.

###### `word_break< V >`

* `V` is of type `UWordBreakValues`.
* [Equivalent] to `property_value< UCHAR_WORD_BREAK, V >`.

### ICU Rules for Value Properties

Convenience wrappers for enumerated properties that return a value instead of an actual `enum`.

###### `canonical_combining_class< V >`

* `V` is of type `std::uint8_t`.
* [Equivalent] to `property_value< UCHAR_CANONICAL_COMBINING_CLASS, V >`.

###### `lead_canonical_combining_class< V >`

* `V` is of type `std::uint8_t`.
* [Equivalent] to `property_value< UCHAR_LEAD_CANONICAL_COMBINING_CLASS, V >`.

###### `trail_canonical_combining_class< V >`

* `V` is of type `std::uint8_t`.
* [Equivalent] to `property_value< UCHAR_TRAIL_CANONICAL_COMBINING_CLASS, V >`.

## Binary Rules

These rules are available in multiple versions,

* in namespace `tao::pegtl::uint8` for 8-bit integer values,
* in namespace `tao::pegtl::uint16_be` for big-endian 16-bit integer values,
* in namespace `tao::pegtl::uint16_le` for little-endian 16-bit integer values,
* in namespace `tao::pegtl::uint32_be` for big-endian 32-bit integer values,
* in namespace `tao::pegtl::uint32_le` for little-endian 32-bit integer values,
* in namespace `tao::pegtl::uint64_be` for big-endian 64-bit integer values, and
* in namespace `tao::pegtl::uint64_le` for little-endian 64-bit integer values.

The binary rules need to be manually included from their corresponding headers in the `contrib` section.

These rules read one or more bytes from the input to form (and match) an 8, 16, 32 or 64-bit value, respectively, and corresponding template parameters are given as either `std::uint8_t`, `std::uint16_t`, `std::uint32_t` or `std::uin64_t`.

In the following descriptions, the parameter N is the size of a single value in bytes, i.e. either 1, 2, 4 or 8.
The term *input value* indicates a correspondingly sized integer value read from successive bytes of the input.

Binary rules do not rely on other rules.

###### `any`

* Succeeds when the input contains at least N bytes.
* Consumes N bytes when it succeeds.

###### `mask_not_one< M, C... >`

* Succeeds when the input contains at least N bytes, and:
* `C` is an empty character pack or the (endian adjusted) input value masked with `M` is **not** one of the given values `C...`.
* Consumes N bytes when it succeeds.

###### `mask_not_range< M, C, D >`

* Succeeds when the input contains at least N bytes, and:
* The (endian adjusted) input value `B` satisfies `( B & M ) < C || D < ( B & M )`.
* Consumes N bytes when it succeeds.

###### `mask_one< M, C... >`

* Succeeds when the input contains at least N bytes, and:
* `C` is a non-empty character pack and the (endian adjusted) input value masked with `M` is one of the given values `C...`.
* Consumes N bytes when it succeeds.

###### `mask_range< M, C, D >`

* Succeeds when the input contains at least N bytes, and:
* The (endian adjusted) input value `B` satisfies `C <= ( B & M ) && ( B & M ) <= D`.
* Consumes N bytes when it succeeds.

###### `mask_ranges< M, C1, D1, C2, D2, ... >`

* [Equivalent] to `sor< mask_range< M, C1, D1 >, mask_range< M, C2, D2 >, ... >`.

###### `mask_ranges< M, C1, D1, C2, D2, ..., E >`

* [Equivalent] to `sor< mask_range< M, C1, D1 >, mask_range< M, C2, D2 >, ..., mask_one< M, E > >`.

###### `mask_string< M, C... >`

* [Equivalent] to `seq< mask_one< M, C >... >`.

###### `not_one< C... >`

* Succeeds when the input contains at least N bytes, and:
* `C` is an empty character pack or the (endian adjusted) input value is **not** one of the given values `C...`.
* Consumes N bytes when it succeeds.

###### `not_range< C, D >`

* Succeeds when the input contains at least N bytes, and:
* The (endian adjusted) input value `B` satisfies `B < C || D < B`.
* Consumes N bytes when it succeeds.

###### `one< C... >`

* Succeeds when the input contains at least N bytes, and:
* `C` is a non-empty character pack and the (endian adjusted) input value is one of the given values `C...`.
* Consumes N bytes when it succeeds.

###### `range< C, D >`

* Succeeds when the input contains at least N bytes, and:
* The (endian adjusted) input value `B` satisfies `C <= B && B <= D`.
* Consumes N byte when it succeeds.

###### `ranges< C1, D1, C2, D2, ... >`

* [Equivalent] to `sor< range< C1, D1 >, range< C2, D2 >, ... >`.

###### `ranges< C1, D1, C2, D2, ..., E >`

* [Equivalent] to `sor< range< C1, D1 >, range< C2, D2 >, ..., one< E > >`.

###### `string< C... >`

* [Equivalent] to `seq< one< C >... >`.

## Full Index

* [`action< A, R... >`](#action-a-r-) <sup>[(meta rules)](#meta-rules)</sup>
* [`alnum`](#alnum) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`alpha`](#alpha) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`alphabetic`](#alphabetic) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`any`](#any) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`any`](#any-1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`any`](#any-2) <sup>[(binary rules)](#binary-rules)</sup>
* [`apply< A... >`](#apply-a-) <sup>[(action rules)](#action-rules)</sup>
* [`apply0< A... >`](#apply0-a-) <sup>[(action rules)](#action-rules)</sup>
* [`ascii_hex_digit`](#ascii_hex_digit) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`at< R... >`](#at-r-) <sup>[(combinators)](#combinators)</sup>
* [`bidi_class< V >`](#bidi_class-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`bidi_control`](#bidi_control) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`bidi_mirrored`](#bidi_mirrored) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`binary_property< P >`](#binary_property-p-) <sup>[(icu rules)](#basic-icu-rules)</sup>
* [`binary_property< P, V >`](#binary_property-p-v-) <sup>[(icu rules)](#basic-icu-rules)</sup>
* [`blank`](#blank) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`block< V >`](#block-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`bof`](#bof) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`bol`](#bol) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`bom`](#bom) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`bytes< Num >`](#bytes-num-) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`canonical_combining_class< V >`](#canonical_combining_class-v-) <sup>[(icu rules)](#icu-rules-for-value-properties)</sup>
* [`case_sensitive`](#case_sensitive) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`control< C, R... >`](#control-c-r-) <sup>[(meta rules)](#meta-rules)</sup>
* [`dash`](#dash) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`decomposition_type< V >`](#decomposition_type-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`default_ignorable_code_point`](#default_ignorable_code_point) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`deprecated`](#deprecated) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`diacritic`](#diacritic) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`digit`](#digit) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`disable< R... >`](#disable-r-) <sup>[(meta rules)](#meta-rules)</sup>
* [`discard`](#discard) <sup>[(meta rules)](#meta-rules)</sup>
* [`east_asian_width< V >`](#east_asian_width-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`enable< R... >`](#enable-r-) <sup>[(meta-rules)](#meta-rules)</sup>
* [`eof`](#eof) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`eol`](#eol) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`eolf`](#eolf) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`everything`](#everything) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`extender`](#extender) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`failure`](#failure) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`forty_two< C... >`](#forty_two-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`full_composition_exclusion`](#full_composition_exclusion) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`general_category< V >`](#general_category-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`grapheme_base`](#grapheme_base) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`grapheme_cluster_break< V >`](#grapheme_cluster_break-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`grapheme_extend`](#grapheme_extend) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`grapheme_link`](#grapheme_link) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`hangul_syllable_type< V >`](#hangul_syllable_type-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`hex_digit`](#hex_digit) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`hyphen`](#hyphen) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`id_continue`](#id_continue) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`id_start`](#id_start) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`identifier_first`](#identifier_first) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`identifier_other`](#identifier_other) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`identifier`](#identifier) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`ideographic`](#ideographic) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`ids_binary_operator`](#ids_binary_operator) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`ids_trinary_operator`](#ids_trinary_operator) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`if_apply< R, A... >`](#if_apply-r-a-) <sup>[(action rules)](#action-rules)</sup>
* [`if_must< R, S... >`](#if_must-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`if_must_else< R, S, T >`](#if_must_else-r-s-t-) <sup>[(convenience)](#convenience)</sup>
* [`if_then_else< R, S, T >`](#if_then_else-r-s-t-) <sup>[(convenience)](#convenience)</sup>
* [`istring< C... >`](#istring-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`join_control`](#join_control) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`joining_group< V >`](#joining_group-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`joining_type< V >`](#joining_type-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`keyword< C... >`](#keyword-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`lead_canonical_combining_class< V >`](#lead_canonical_combining_class-v-) <sup>[(icu rules)](#icu-rules-for-value-properties)</sup>
* [`line_break< V >`](#line_break-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`list< R, S >`](#list-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`list< R, S, P >`](#list-r-s-p-) <sup>[(convenience)](#convenience)</sup>
* [`list_must< R, S >`](#list_must-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`list_must< R, S, P >`](#list_must-r-s-p-) <sup>[(convenience)](#convenience)</sup>
* [`list_tail< R, S >`](#list_tail-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`list_tail< R, S, P >`](#list_tail-r-s-p-) <sup>[(convenience)](#convenience)</sup>
* [`logical_order_exception`](#logical_order_exception) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`lower`](#lower) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`lowercase`](#lowercase) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`mask_not_one< M, C... >`](#mask_not_one-m-c-) <sup>[(binary rules)](#binary-rules)</sup>
* [`mask_not_range< M, C, D >`](#mask_not_range-m-c-d-) <sup>[(binary rules)](#binary-rules)</sup>
* [`mask_one< M, C... >`](#mask_one-m-c-) <sup>[(binary rules)](#binary-rules)</sup>
* [`mask_range< M, C, D >`](#mask_range-m-c-d-) <sup>[(binary rules)](#binary-rules)</sup>
* [`mask_ranges< M, C1, D1, C2, D2, ... >`](#mask_ranges-m-c1-d1-c2-d2--) <sup>[(binary rules)](#binary-rules)</sup>
* [`mask_ranges< M, C1, D1, C2, D2, ..., E >`](#mask_ranges-m-c1-d1-c2-d2--e-) <sup>[(binary rules)](#binary-rules)</sup>
* [`mask_string< M, C... >`](#mask_string-m-c-) <sup>[(binary rules)](#binary-rules)</sup>
* [`math`](#math) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`minus< M, S >`](#minus-m-s-) <sup>[(convenience)](#convenience)</sup>
* [`must< R... >`](#must-r-) <sup>[(convenience)](#convenience)</sup>
* [`nfc_inert`](#nfc_inert) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`nfd_inert`](#nfd_inert) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`nfkc_inert`](#nfkc_inert) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`nfkd_inert`](#nfkd_inert) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`noncharacter_code_point`](#noncharacter_code_point) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`not_at< R... >`](#not_at-r-) <sup>[(combinators)](#combinators)</sup>
* [`not_one< C... >`](#not_one-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`not_one< C... >`](#not_one-c--1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`not_one< C... >`](#not_one-c--2) <sup>[(binary rules)](#binary-rules)</sup>
* [`not_range< C, D >`](#not_range-c-d-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`not_range< C, D >`](#not_range-c-d--1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`not_range< C, D >`](#not_range-c-d--2) <sup>[(binary rules)](#binary-rules)</sup>
* [`nul`](#nul) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`numeric_type< V >`](#numeric_type-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`one< C... >`](#one-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`one< C... >`](#one-c--1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`one< C... >`](#one-c--2) <sup>[(binary rules)](#binary-rules)</sup>
* [`opt< R... >`](#opt-r-) <sup>[(combinators)](#combinators)</sup>
* [`opt_must< R, S...>`](#opt_must-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`pad< R, S, T = S >`](#pad-r-s-t--s-) <sup>[(convenience)](#convenience)</sup>
* [`pad_opt< R, P >`](#pad_opt-r-p-) <sup>[(convenience)](#convenience)</sup>
* [`partial< R... >`](#partial-r-) <sup>[(convenience)](#convenience)</sup>
* [`pattern_syntax`](#pattern_syntax) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`pattern_white_space`](#pattern_white_space) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`plus< R... >`](#plus-r-) <sup>[(combinators)](#combinators)</sup>
* [`posix_alnum`](#posix_alnum) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`posix_blank`](#posix_blank) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`posix_graph`](#posix_graph) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`posix_print`](#posix_print) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`posix_xdigit`](#posix_xdigit) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`print`](#print) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`property_value< P, V >`](#property_value-p-v-) <sup>[(icu rules)](#basic-icu-rules)</sup>
* [`quotation_mark`](#quotation_mark) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`radical`](#radical) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`raise< T >`](#raise-t-) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`raise_message< C... >`](#raise_message-c-) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`range< C, D >`](#range-c-d-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`range< C, D >`](#range-c-d--1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`range< C, D >`](#range-c-d--2) <sup>[(binary rules)](#binary-rules)</sup>
* [`ranges< C1, D1, C2, D2, ... >`](#ranges-c1-d1-c2-d2--) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`ranges< C1, D1, C2, D2, ... >`](#ranges-c1-d1-c2-d2---1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`ranges< C1, D1, C2, D2, ... >`](#ranges-c1-d1-c2-d2---2) <sup>[(binary rules)](#binary-rules)</sup>
* [`ranges< C1, D1, C2, D2, ..., E >`](#ranges-c1-d1-c2-d2--e-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`ranges< C1, D1, C2, D2, ..., E >`](#ranges-c1-d1-c2-d2--e--1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`ranges< C1, D1, C2, D2, ..., E >`](#ranges-c1-d1-c2-d2--e--2) <sup>[(binary rules)](#binary-rules)</sup>
* [`rematch< R, S... >`](#rematch-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`rep< Num, R... >`](#rep-num-r-) <sup>[(convenience)](#convenience)</sup>
* [`rep_max< Max, R... >`](#rep_max-max-r-) <sup>[(convenience)](#convenience)</sup>
* [`rep_min< Min, R... >`](#rep_min-min-r-) <sup>[(convenience)](#convenience)</sup>
* [`rep_min_max< Min, Max, R... >`](#rep_min_max-min-max-r-) <sup>[(convenience)](#convenience)</sup>
* [`rep_opt< Num, R... >`](#rep_opt-num-r-) <sup>[(convenience)](#convenience)</sup>
* [`require< Num >`](#require-num-) <sup>[(meta-rules)](#meta-rules)</sup>
* [`s_term`](#s_term) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`segment_starter`](#segment_starter) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`sentence_break< V >`](#sentence_break-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`seq< R... >`](#seq-r-) <sup>[(combinators)](#combinators)</sup>
* [`seven`](#seven) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`shebang`](#shebang) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`soft_dotted`](#soft_dotted) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`sor< R... >`](#sor-r-) <sup>[(combinators)](#combinators)</sup>
* [`space`](#space) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`star< R... >`](#star-r-) <sup>[(combinators)](#combinators)</sup>
* [`star_must< R, S... >`](#star_must-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`star_partial< R... >`](#star_partial-r-) <sup>[(convenience)](#convenience)</sup>
* [`star_strict< R... >`](#star_strict-r-) <sup>[(convenience)](#convenience)</sup>
* [`state< S, R... >`](#state-s-r-) <sup>[(meta rules)](#meta-rules)</sup>
* [`strict< R... >`](#strict-r-) <sup>[(convenience)](#convenience)</sup>
* [`string< C... >`](#string-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`string< C... >`](#string-c--1) <sup>[(unicode rules)](#unicode-rules)</sup>
* [`string< C... >`](#string-c--2) <sup>[(binary rules)](#binary-rules)</sup>
* [`success`](#success) <sup>[(atomic rules)](#atomic-rules)</sup>
* [`TAO_PEGTL_ISTRING( "..." )`](#tao_pegtl_istring--) <sup>[(ascii rules)](#ascii_rules)</sup>
* [`TAO_PEGTL_KEYWORD( "..." )`](#tao_pegtl_keyword--) <sup>[(ascii rules)](#ascii_rules)</sup>
* [`TAO_PEGTL_RAISE_MESSAGE( "..." )`](#tao_pegtl_raise_message--) <sup>[(atomic rules)](#atomic_rules)</sup>
* [`TAO_PEGTL_STRING( "..." )`](#tao_pegtl_string--) <sup>[(ascii rules)](#ascii_rules)</sup>
* [`terminal_punctuation`](#terminal_punctuation) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`three< C >`](#three-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`trail_canonical_combining_class< V >`](#trail_canonical_combining_class-v-) <sup>[(icu rules)](#icu-rules-for-value-properties)</sup>
* [`try_catch_any_raise_nested< R... >`](#try_catch_any_raise_nested-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_any_return_false< R... >`](#try_catch_any_return_false-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_raise_nested< R... >`](#try_catch_raise_nested-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_return_false< R... >`](#try_catch_return_false-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_std_raise_nested< R... >`](#try_catch_std_raise_nested-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_std_return_false< R... >`](#try_catch_std_return_false-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_type_raise_nested< E, R... >`](#try_catch_type_raise_nested-e-r-) <sup>[(convenience)](#convenience)</sup>
* [`try_catch_type_return_false< E, R... >`](#try_catch_type_return_false-e-r-) <sup>[(convenience)](#convenience)</sup>
* [`two< C >`](#two-c-) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`unified_ideograph`](#unified_ideograph) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`until< R >`](#until-r-) <sup>[(convenience)](#convenience)</sup>
* [`until< R, S... >`](#until-r-s-) <sup>[(convenience)](#convenience)</sup>
* [`upper`](#upper) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`uppercase`](#uppercase) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`variation_selector`](#variation_selector) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`white_space`](#white_space) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`word_break< V >`](#word_break-v-) <sup>[(icu rules)](#icu-rules-for-enumerated-properties)</sup>
* [`xdigit`](#xdigit) <sup>[(ascii rules)](#ascii-rules)</sup>
* [`xid_continue`](#xid_continue) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>
* [`xid_start`](#xid_start) <sup>[(icu rules)](#icu-rules-for-binary-properties)</sup>

---

This document is part of the [PEGTL](https://github.com/taocpp/PEGTL).

Copyright (c) 2014-2023 Dr. Colin Hirsch and Daniel Frey
Distributed under the Boost Software License, Version 1.0<br>
See accompanying file [LICENSE_1_0.txt](../LICENSE_1_0.txt) or copy at https://www.boost.org/LICENSE_1_0.txt

[Equivalent]: #equivalence
[implementation]: #implementation
[Incremental Input]: Inputs-and-Parsing.md#incremental-input
[Meta data]: Meta-Data-and-Visit.md