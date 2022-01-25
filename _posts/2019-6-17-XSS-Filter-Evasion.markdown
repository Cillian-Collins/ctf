---
layout: post
title: XSS Filter Evasion
author: Cillian
tags: [xss, filter evasion]
---

You're testing a web application and finally find an endpoint that is reflecting HTML code. You drop your XSS payload and BOOM! All your hopes and dreams vanish before your eyes as that damn WAF appears out of nowhere, only to laugh at you.

<!-- read more -->

In this blog post I'm going to be detailing how I successfully bypassed an XSS filter to achieve a very interesting reflected XSS vulnerability in an obvious endpoint which had clearly been tested by hundreds of security researchers before me.
This vulnerability just so happens to be the very same one that my 2nd challenge over on [My Challenge Site](http://m0z.altervista.org).

## The Beginning

Lets take it back to where it all started. I think this vulnerability emphasizes the fact that every little piece of information can be useful at a later date. I noticed that the website I was testing was reflecting the input of a parameter inside of an input tag. This is pretty standard behaviour and it looked something like:

`<input name="param1" value=$param1>`

The idea is that the corresponding value of the GET parameter `param1` is reflected into the above input box's value. The input is escaped correctly, so the tag cannot be closed, and furthermore the characters `>` and `<` are completely blocked by the WAF making it virtually impossible to spawn your own HTML tags.
The one detail you might notice about this scenario is the the value of `$param1` is not enclosed within any quotations, meaning that we can spawn a new attribute on that very same input tag by dropping a space.
So now it seems as though we've cracked it, we can drop a space and use the `onfocus` event handler, along with the `autofocus` attribute to instantly execute our javascript the moment a victim visits our link. But of course this is real life, so things are never that simple!

## The WAF

Introducing the WAF (edgy music). WAF stands for "Web Application Firewall", or alternativelty "What the Actual Fuck?!" which tends to be most security researcher's reaction when they encounter it. WAF is a close relative of the equally annoying "Content Security Policy" but thankfully I didn't have to deal with that in this case so we'll leave that for another blog post.
The WAF was doing 2 really distinct actions. Firstly it was completely blocking any requestions which contained HTML, which included all event handlers (`onfocus`). Secondly it was stripping key javascript functions such as `alert`, `prompt`, `console.log` and pretty much everything you would ever need for an XSS PoC. It even stripped `document.cookie`!
It sounds pretty secure, we're blocked from adding any event handlers, which means there is literally no way we can obtain XSS, and this is true, I didn't find some magical way of bypassing that. I tried a lot of different handlers but in the end none of them were allowed.
The actual solution to this lies in their "additional security measures", which in this case was their stripping of keywords such as `alert`, `prompt`, etc. I had to think outside the box and realized a realistic attack scenario which would work in the event that the stripping happened after the blocks, which it usually would!
The blocks were being incurred by the WAF, which read the request data before the web application ever got its hands on it. That way it could safely discard it. But then the web application was stripping those javascript keywords, which happened afterwards. The idea was to create a payload that when sent would not be blocked by the WAF, but once the application received it and stripped those keywords, it would now be a working payload.

## Getting The PoC
Finally it was time to fire up a payload. We know the `onload` event handler is being blocked. We know `alert` and `document.cookie` are also both being stripped.
So I decided that `alert` would be my 'packaging' which would allow me to package up the payload so that it safely evaded the WAF, but was then discarded by the web application.
The final payload:

` oalertnfocus=alalertert(documealertnt.cookie) autofocus`

Which combined to spawn the full input element on the page after the `alert` keyword was stripped:

`<input name="param1" value= onfocus=alert(document.cookie) autofocus>`

## The End
 I know this post was short, but I'm hoping it provided you with some thought-provoking material with regards to WAF bypassing techniques, as well as web application created filter evasion. If you have any questions, feel free to message me on twitter [@LooseSecurity](https://twitter.com/loosesecurity) or join my [Discord](https://discord.gg/qStuRZS). I'm always happy to help! Thanks for reading & I hope you learned something new from this article.
