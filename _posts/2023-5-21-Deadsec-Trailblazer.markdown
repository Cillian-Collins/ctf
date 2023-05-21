
---
layout: post
title: Deadsec — TrailBlazer
author: Cillian (Team Ireland Without RE)
tags: [ctf, web]
---

In this post I'll walk you through how I solved the Trailblazer challenge.

<!-- read more -->

## Initial Assessment
```
Are you ready to blaze a trail and become a champion?
```

The challenge description and name doesn't give us much information. The main page displays a the text `[0-9 a-z A-Z / " \+ , ( ) . # \[ \] =]`. Seems like a regex? Without any source, and very little to go on, I decided to manually check for some common files such as `robots.txt` and `sitemap.xml`.

Doing this displayed a standard 404 error page. But wait! There's something different here.

![404 Error Page](https://i.imgur.com/zYJo2oM.png)

The timestamp at the bottom seems to dynamically change. Viewing the page source, it's being pulled from the endpoint `/images/now`

This seems interesting. Someone on my team noticed that adding certain characters before `now` resulted in us getting blocked with the error message `Bad booiiii`. Any invalid path would result in an `Error`.

## Fuzzing /images/now
I started by manually fuzzing the endpoint. Could we find any characters which would result in a different error? Perhaps a SQL injection, or something of the sort.
I eventually noticed that adding whitespace at the end of the endpoint didn't cause any errors and the image loaded as normal! This threw me off a bit, as I began to suspect CRLF injection may be a potential solution. Spoiler: It wasn't.

I suspected that we would need to add something after `now`. I loaded up a number of different wordlists from [SecLists](https://github.com/danielmiessler/SecLists) and ran them through [ffuf](https://github.com/ffuf/ffuf) to see if anything interesting would happen. I excluded any results which displayed either `Error` or `Bad booiiii`. 

One of these produced an interesting result. A SQLi payload passing ` or 1 > 2` after `now` produced a valid image. I immediately got excited at the prospect of a blind SQLi vulnerability and I loaded up the page only to be greeted with the following:
![/images/now endpoint](https://i.imgur.com/Lwyz9Xo.jpg)

Well, it looks like we are actually injecting into some Python code. I'm not exactly sure what is causing this, but I think it may be an eval. Anyway, now we just need to get RCE from here, so we will need to use our PyJail knowledge to break out of this!

## Getting The Flag
We are able to view the "now" object. I assumed this was `datetime.now` from the `datetime` Python module. I started playing around with this locally to see if I could get it working. The payload `now.__class__.__bases__[0].__subclasses__()` will give us a nice list of all subclasses. Here, we need something a bit dangerous like BuiltinImporter or `os._wrap_close`. I'm sure there are cleaner solutions to pick out the offset of these from the list, but in full CTF spirit I just manually started checking numbers around the range I expected to find them and discovered `os._wrap_close` at offset `133`.

Full URL:
`/images/now.__class__.__bases__[0].__subclasses__()[133] or 1 > 2`

Next, I needed to get RCE using this module:
`/images/now.__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['popen']('cat flag.txt').read() or 1 > 2`

![Flag](https://i.imgur.com/30ux1u0.jpg)

Unfortunately, the flag is truncated. There are a few options here, perhaps just loading a reverse shell. I decided to just pipe it into `rev` and reverse the flag. I could then read the last part of the flag backwards and tidy it up.

## Final Notes
Credit to other Team Ireland Without RE members who helped out with this. You can find me on Twitter [@LooseSecurity](https://twitter.com/LooseSecurity).
