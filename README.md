# A Modest Content Security Proposal

Mike West, July 2019 (©2019, Google)

**TL;DR**: _Let's break CSP in half and throw away some options while we're at it._

Content Security Policy is a thing. We've been iterating on it for years and years now, and it
shows. The backwards compatibility constraints are increasingly contorted, we've moved right
past scope _creep_ into scope _kudzu_, and the implementation status between browsers is
inconsistent at best. I think it would be somewhat irresponsible to make these problems worse by
starting on another iteration of CSP that did anything other than remove features, and I don't
intend to do so.

In fact, let's think about the opposite approach: as a thought experiment, let's say we disabled CSP
support in Chromium tomorrow. What would we be losing? What problems does it address that we care
about? What mechanisms might we put into place to address them?

I think CSP is aiming to address three distinct problems:

1.  **XSS mitigation**: We'd like to make it hard for attackers to inject script into pages in a way
    that causes execution. <https://csp.withgoogle.com/docs/strict-csp.html> outlines the approach
    taken inside Google, which has greatly influenced the design of CSP3. It also, of course, makes
    many aspects of CSP1 and CSP2 irrelevant cruft.

2.  **Resource confinement**: Facebook and others use CSP as a mechanism for constraining their
    developers to a known-good set of origin servers, preventing them from creating dependencies on
    untrusted resources. It's also pretty reasonable to want to use CSP as a confinement mechanism
    that could mitigate data exfiltration, but it's not defined in a way that makes it easy to
    address that threat model.

3.  **Policy delivery**: CSP exists, which makes it a very convenient thing to glom onto for new
    features.
    [`Upgrade-Insecure-Requests`](https://w3c.github.io/webappsec-upgrade-insecure-requests/#delivery),
    [`Block-All-Mixed-Content`](https://w3c.github.io/webappsec-mixed-content/#strict-checking),
    [`navigate-to`](https://w3c.github.io/webappsec-csp/#navigate-to),
    [`plugin-types`](https://w3c.github.io/webappsec-csp/#directive-plugin-types), and (maybe?)
    [Trusted Types](https://w3c.github.io/webappsec-trusted-types/dist/spec/) are all examples of things
    that, in hindsight, used CSP as a delivery mechanism mostly because it was already there.

I now consider the third of these to be a misfeature, and would prefer to invent new delivery
mechanisms for new things. These should rely on general-purpose primitives like
[Structured Headers](https://tools.ietf.org/html/draft-ietf-httpbis-header-structure), the
[Reporting API](https://w3c.github.io/reporting/), and
[Origin Policy](https://wicg.github.io/origin-policy/), and shouldn't attach themselves to something
generic and sprawling.

The first two, however, are important use cases to support. Knowing what we know today, thanks to a
few years of deployment experience with CSP, I think we'd approach both differently. How, you ask?
An excellent question, which is happily addressed in the following two sections of this document.


## XSS Mitigation

The [ARTUR proposal](https://mikewest.github.io/artur-yes/) is a silly suggestion that is obviously
a bad idea as specified, but seems like a really good idea conceptually. If we step back a bit from
CSP's current syntax, it seems like we can boil down the requirements for Google's
[strict CSP recommendations](https://csp.withgoogle.com/docs/strict-csp.html) to:

1.  Turn off dangerous parts of the platform that influence scripting, like `<base>`, `<object>`, and `<embed>`.

2.  Rely on some out-of-band signal that a given `<script>` element (and maybe its dependencies (and
    maybe scripty attributes like event handlers)) should execute. This signal boils down to a
    [`nonce`](https://csp.withgoogle.com/docs/faq.html#generating-nonces) or a hash delivered in an
    HTTP header and reflected in a [`nonce`](https://html.spec.whatwg.org/#nonce-attributes) or
    [`integrity`](https://html.spec.whatwg.org/#attr-link-integrity) attribute, respectively.

3.  Deploy CSP in report-only mode to discover and fix bugs before rolling it out with enforcement
    enabled.

What might it look like if we extracted a minimal subset of CSP that could handle this set of
requirements? I (somewhat unsurprisingly) think it would look a lot like
[ARTUR](https://mikewest.github.io/artur-yes/). We could support a list of hashes, a list of nonces,
and a few flags to control the behavior. Most users would be well-served with:

```
Scripting-Policy: nonce="number-used-once"
```

which would have the effect of:

1.  Executing [parser-inserted](https://html.spec.whatwg.org/multipage/scripting.html#parser-inserted)
    script iff it has a `nonce` attribute matching the specified nonce, and executing all
    non-[parser-inserted](https://html.spec.whatwg.org/multipage/scripting.html#parser-inserted)
    script.

2.  Preventing `<base>` from pointing relative URLs cross-origin.

3.  Allowing <code>eval([TrustedScript](https://w3c.github.io/webappsec-trusted-types/dist/spec/#trusted-script))</code>,
    while blocking its <code>[DOMString](https://heycam.github.io/webidl/#idl-DOMString)</code>-based variant.

4.  Blocking inline event handlers, XSLT, `javascript:` URLs, `<object>`, and `<embed>`.

In the presence of an Origin Policy opt-in (or user agent perogative for some class of website
(PWAs?)), it might even be possible to require these behaviors _by default_ by inverting the nonce
generation logic such that the _client_ generates a nonce, and delivers it to the server along with
all navigational requests:

```
Sec-Script-Nonce: "client's number-used-once"
```

The user agent would recall this nonce when processing the response, applying something like
`Scripting-Policy: nonce="client's number-used-once"` unless the server explicitly overrode it
with a `Scripting-Policy` declaration in the response (or some sort of similarly explicit
`I-Dont-Like: Scripting-Policy` opt-out).

### Flexibility and Options

Of course, there are users for whom this set of default behavior won't be a good fit. That's fine.
We can add some optional options to allow some flexibility:

1.  Script can be gated on a list of SHA-256 hashes rather than (or in addition to) a nonce. Hashes
    can match inline script, external script (by
    [layering on top of SRI](https://w3c.github.io/webappsec-csp/#external-hash)), and inline event
    handlers.

    ```
    Scripting-Policy: hashes=(hash1 hash2 hash3 hash4)
    ```

2.  Dynamically-loaded script's behavior is controlled via a `dynamic-loading` member whose value is
    one of "`always-allowed`" or "`checked`". The former is the default behavior, allowing
    non-parser-inserted script to execute without further checks. The latter applies the same nonce
    and/or hash checks as would be applied to parser-inserted script.

    ```
    Scripting-Policy: nonce="abcdefg", dynamic-loading=checked
    ```

    _ISSUE: We can easily support workers in `dynamic-loading=always-allowed` mode, but what about
    `checked`? CSP hasn't yet created a sane way of injecting nonces into those constructors.
    `importScripts()`, `<script type="module">`, and `import` all present similar problems._

3.  `eval()`'s behavior is controlled via an `eval` member whose value is one of "`allow`",
    "`block`", or "`allow-trusted`". "`allow-trusted`" would block
    <code>eval([DOMString](https://heycam.github.io/webidl/#idl-DOMString))</code>, but allow
    <code>eval([TrustedScript](https://w3c.github.io/webappsec-trusted-types/dist/spec/#trusted-script))</code>.
    `allow-trusted` is the default behavior.

    ```
    Scripting-Policy: nonce="abcdefg", eval=block
    ```

4.  On the subject of Trusted Types, let's jam those into this syntax as well via `trusted-types-policy` and `trusted-types-required-for` members.

    ```
    Scripting-Policy: nonce="abcdefg",
	                    trusted-types-policy="name",
	                    trusted-types-required-for=(type1 type2 type3 type4)
    ````

5.  The policy can be wired up to the reporting API via a `report-to` member.

    ```
    Scripting-Policy: nonce="abcdefg", report-to=reporting-endpoint
    ```

6.  A report-only policy can be specified via `Scripting-Policy-Report-Only`.

    ```
    Scripting-Policy-Report-Only: nonce="abcdefg",
	                                report-to=reporting-endpoint
    ```

Note that no option is provided to relax `<base>` to allow cross-origin endpoints, nor any to enable
plugins, `javascript:` URLs or XSLT. I expect someone will quickly tell me that this is unworkable
and that we need `plugins`, `javascript-urls`, and `xslt` boolean members, which will be annoying.

Similarly, no option is provided to specify a policy inline in a document via `<meta>`.

So, advanced deployments of the world might send:

```
Scripting-Policy: hashes=(hash1 hash2 hash3 hash4),
                  report-to=name,
                  trusted-types-policy=policyName
Scripting-Policy-Report-Only: hashes=(hash1 hash2 ...hash18 ... hash37),
                              eval=block,
                              dynamic-loading=checked,
                              report-to=name,
                              trusted-types-policy=policyName
```


## Resource Confinement

_Caveat: insomuch as I've thought about any of this, the confinement story is less clear to me than
the XSS mitigation story. Feedback on this section would be very much appreciated, as this section
is pretty clearly nothing more than a sketch at this point._

Developers often wish to enforce constraints on the hosts from which particular kinds of resources
can be loaded. This desire generally reflects one or both of the following requirements:

1.  **Exfiltration mitigation** prevents data from being delivered to unexpected endpoints by
    requiring blanket evaluation of all requests (subresources, preloads, frames, etc.) initiated
    from a given context.

2.  **Dependency management** allows developers to enforce
    [origin hygiene](https://lists.w3.org/Archives/Public/public-webappsec/2016Jun/0011.html) by
    constraining the hosts from which they load particular kinds of resources. This capability can
    be satisfied by an exfiltration mitigation mechanism, but would likely benefit from granular
    control over requests of specific types. Scripts might come from one set of servers, for
    example, while media comes from another.

Sites with simple needs would likely be satisfied with a blanket restriction on a given context's
ability to initiate requests to unknown hosts. Something like the following might suffice:

```
	Confinement-Policy:
	    known-host-suffixes=("good.site" "not-an-attacker.page" "cdn.me")
```

This policy would block subresource requests of any type (frames, images, prefetch/-render, scripts,
etc.) unless they targeted an origin which was considered secure, and whose host's rightmost DNS
labels were contained within the `known-host-suffixes` list. Top-level navigations would be allowed,
as would requests targeting resources that would not cause network requests (`data:`, `blob:`,
`filesystem:`).

I suspect that this simple approach would handle 80% of how people use CSP for confinement today.
There might not be enough value in the other 20% to support more complicated policies. But, keeping
that in mind, let's assume for a moment that complicated people in the world really would require
complex policies with something more than blanket-level granularity. Something like the following
would be more or less as flexible as CSP today:

```
  Confinement-Policy-Sets:
      my_cdns=("good.site" "not-an-attacker.page" "cdn.me"),
      image_set=("another.cdn" "images-r.us")
      video_set=("videos.cat" "pawtube.animals")
      audio_set=("podcasts.fm")
  Confinement-Policy:
    script=(my_cdns),
    media=(image_set video_set audio_set my_cdns)
```

This policy would define a number of sets of host suffixes, and uses those sets to define
constraints on script (e.g. `<script>`, `new Worker(...)`, `importScripts()`, etc.) and media (e.g.
`<img>`, `<video>`, `<audio>`) resource fetches. Fetches for other resource types (frames, style,
fonts, and so on) are unrestricted.

This, of course, leads to a few questions:

1.  **Categorization**?  We'd likely want to break things down along similar lines as CSP's
    [fetch directives](https://w3c.github.io/webappsec-csp/#directives-fetch), though I think we can
    get away with less granularity: maybe `script`, `style`, `media` (audio, video, images),
    `frames`, `workers`, and a catch-all `default`? An alternative would be to expose Fetch's
    ([initiator](https://fetch.spec.whatwg.org/#concept-request-initiator),
    [destination](https://fetch.spec.whatwg.org/#concept-request-destination)) pair directly, but
    that seems unlikely to be comprehensible for developers generally, and summarized categories are
    likely the right choice.

2.  **Origins vs suffixes**? Suffixes seem more likely to match what developers actually want, but
    if folks do require more granularity, it seems trivial to support with some explicit "This is an
    origin!" syntax. Perhaps a leading `.` (e.g. `.example.com` vs `example.com`)?

3.  **Paths**? Paths in CSP are pretty complicated due to the redirect behavior where we throw them
    away. I suspect we wouldn't get much actual confinement value out of them unless we also
    provided more control over the ability for a request to redirect itself somewhere other than
    what the page expects. Perhaps that's valuable? I'm not sure it is. Sites using CSP for
    confinement today don't appear to make much use of path-based restrictions, and we can probably
    get away without it.


## FAQ

### CSP exists. Is this worth doing?

Probably not, unfortunately.

I go back and forth between believing that many more developers could use a thing that was more
narrowly targeted and defined, and believing that it can't possibly be worth throwing away CSP for
something that's basically offering the same capabilities in a friendlier form.

Still, it's a good topic for discussion, so I typed it up! :)

### Let's say we did some of this. What about CSP?

While the underlying implementation might use some of the same pathways as existing CSP
implementations, there would be no developer-facing linkage between them. Developers could use both
at the same time (but doing so would probably make them sad). The goal would be to deprecate CSP in
favor of this mechanism for XSS mitigation generally, and eventually remove support from the
browser.
