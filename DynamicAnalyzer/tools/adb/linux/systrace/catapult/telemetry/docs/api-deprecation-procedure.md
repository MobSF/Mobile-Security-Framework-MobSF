# Telemetry API Deprecation Procedure

## Procedure for hard deprecation:
1. Determine a deprecation time-frame.
2. Create documentation on suggested refactor/workarounds if applicable.
3. Apply applicable warnings for users about the deprecation.
4. Announce deprecation.
5. (Optional) Audit important users for usage of deprecated code prior to deletion.
6. Delete the offending code.

## Determine deprecation time-frame.

The default time-frame is 18 weeks. If the expected user refractors are expected to take more than a third of that time to complete, this timeframe may be extended on a case-by-case basis as appropriate prior to announcement.

## Create documentation on suggested refactor/workarounds if applicable.

If a large refactor is expected for the users to stop using the deprecated code, documentation with suggested alternatives should be created. This may include examples (placed in the examples folder in the appropriate location), a wiki page documenting the change and/or our suggested workarounds/refactors, and/or a link to any replacement features.

## Apply applicable warnings for users about the deprecation.

This should include any applicable documentation (or links there to), deprecation deadline (as determined in step 1).

### For Python code:

1. All functions and classes to be deprecated should use a deprecation decorator.
   You must pass in the deprecation deadline as determined by step 1 (counted from time of the CL containing these changes) into the decorator. The decorator will contain a warning message using the DeprecationWarning category and outlining the following:
   * A warning of the function being deprecated.
   * The deadline to refactor their code before the function is deleted.
   * An (externally available) email they can use to contact us requesting an extension to the proposed deletion date.
   * A warning that the deadline will only rarely be extended, and only for cases with obvious need and significant forewarning.

2. All functions should log links to any applicable documentation for refactoring, or references to replacement API.

## Announce deprecation
An email should be sent out to telemetry-announce@chromium.org announcing the API being deprecated, the reason(s) for the deprecation, the deprecation deadline, and include any (links to) documentation.
Extension of deprecation deadline
This should happen extremely rarely, if ever. If a user brings up extenuating circumstances, contributors may be asked to give input, and are welcome to make suggestions, on whether we should give an extension to the deadline. The final decision is at the discretion of the PM and TL/TLM for the team owning the portion of the codebase in question, and should take any blocked future work for the product, and timeliness of the request into account.

## (Optional) Audit important users for usage of deprecated code prior to deletion.

In some circumstances, it may be worthwhile to check chromium (or other important users) for usage of deprecated API’s prior to deletion. It may be done on a case by case basis as needed for deprecation of important features.

## Delete the offending code.
1. Commit CL deleting code.
2. ???
3. Profit.
