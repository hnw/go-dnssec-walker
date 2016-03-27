walker(1) -- Retrieve a DNS zone using NSEC traversal
=================

## SYNOPSIS

`walker [-s <startfrom>] [-p <port>] [-d] [@nameserver] <zone>`

## DESCRIPTION

`walker` retrieves a DNS zone from the default or supplied name server and prints each record to the standard output. It does this through NSEC-walking (following the chain of NSEC records) and 'guessing' the next non-existent owner name for each NSEC (just like [DNSSEC Walker](https://josefsson.org/walker/) or `ldns-walk(1)`).

Of course the nameserver that is used must be DNSSEC-aware.

## OPTIONS

<dl>
    <dt>-s &lt;startfrom&gt;</dt>
    <dd>Optional name to start the zone walk at.  The default is to start walking from the start.  This option is useful if the tool failed or was intterupted in the middle of a large zone.</dd>

    <dt>-p &lt;port&gt;</dt>
    <dd>Send the query to a non-standard port on the server, instead of the defaut port 53. This option would be used to test a name server that has been configured to listen for queries on a non-standard port number.</dd>

    <dt>-d</dt>
    <dd>Enable debugging</dd>

    <dt>@nameserver</dt>
    <dd>Send the queries to this nameserver.</dd>
</dl>


## EXAMPLE

```
$ walker -s zunko moe
zunko.moe.
zuo.moe.
zxz.moe.
zyii.moe.
zyon.moe.
zzz.moe.
```

## References

* [DNSSEC Walker](https://josefsson.org/walker/)
* [ldns](http://www.nlnetlabs.nl/projects/ldns/)
* [miekg/dns: DNS library in Go](https://github.com/miekg/dns)


## LICENSE

The MIT License

Copyright (c) 2016 Yoshio HANAWA

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
