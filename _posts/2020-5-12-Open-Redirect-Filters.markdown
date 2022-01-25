---
layout: post
title: Open Redirect Filters
author: Cillian
tags: [open redirect, bug bounty]
---

Today I'm writing about Open Redirect bypasses since it was my first bug I have found since returning. One I normally don't bother reporting as it's not usually very high paying and damages impacts ratings on H1. Nonetheless, Open Redirects are a nice starting point for any security researcher and it seems almost all of them require a filter bypass.

<!-- read more -->

## Locating Endpoints

Finding an open redirect is not an easy task. There tends to be several examples of people using google dorks to achieve this. Personally, I don't tend to use dorks too often with bug bounty programs as it tends to be a previously exausted scope.
Almost every beginner researcher makes the mistake of incorrectly identifying an open redirect. In short, a web application can redirect using the ``location`` header, a javascript ``window.location.href`` and a ``<meta>`` tag in HTML.
These three options will now be explored, detailing the key differences and how they can be used to find vulnerabilities other than an open redirect, and which one should actually be reported.

## Location Header

This is the only one which actually constitutes an open redirect by definition. This is of course an opinion, and it's always disputed by different researchers. My reason for stating this is that the location header can be used for SSRF filter bypassing. What this means is that if you get a web application to send a request to this, it will redirect them elsewhere.
The other two types require the user to actually load the HTML. This can be problematic, as if you're getting a SSRF, the chances are it won't be loading the HTML/JS files (as that would require a browser, although it works with things like Selenium).
If a SSRF successfully redirect a javascript/meta tag, this means you could potentially use a DNS rebinding attack, and it opens a whole other layer of vulnerabilites which could result in RCE.
Without going too much off topic, what you should check when you notice location header injection is:

* Can you perform CRLF injection? Try a %0a%0d payload. If this allows you to inject a new header, then try a double CSRF (which tells the browser receiving the request that the headers are complete). After this you can put script tags which will be loaded to give you CRLFi => rXSS.
* Is there user interaction? If there is user interaction required (ie you must login, or click a button, to be redirected) then it's useless. The only positive here is that you are able to inject the URL into the HTML (since it's putting it as a parameter on a login or a link). You should try ``javascript:`` URI here, which may give you what I call "Bomb XSS". This is XSS which is stored in a page but requires user interaction. If this user interaction is "expected", such as a login page where we expect someone to login, then it increases the severity greatly.

## Javascript Redirect

For javascript redirects you will want to find where the ``window.location.href`` redirect is being set. Try to inject javascript here and achieve XSS. This is about all you can realistically do here.

## Meta Tag

Again, you will realistically want to achieve XSS here. It's not a traditional open redirect so I wouldn't personally deem it to be 

## Filter Evasion

Okay so imagine you have found location header injection with a valid open redirect. You are going to often need to bypass the filter. Here are the methods I usually try, in order of attempt, imagining that we wish to redirect to ``https://google.com/``:

* //google.com
* ///google.com
* \/\/google.com
* google%E3%80%82com
* @google.com

Note: The initial four are always used where the input is reflected into the header alone. This means there is nothing prepending it. Sometimes an open redirect will only redirect you to a page. Example: ``website.com/redirect.php?url=/admin/``. This would redirect to ``/admin/`` => ``website.com/admin/``. In this instance, using ``@google.com`` => ``website.com@google.com`` which redirects to ``google.com``. The point to note is that there must be no slash between the initial URL and the input.
