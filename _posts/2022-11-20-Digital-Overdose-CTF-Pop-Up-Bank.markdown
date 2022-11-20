
---
layout: post
title: Digital Overdose CTF — Pop-Up Bank
author: Cillian (Team Ireland Without RE)
tags: [ctf, web]
---

In this post I'll walk you through how I solved the Pop-Up Bank challenge at the Digital Overdose CTF 2022. In the end, this challenge was only solved by 4 teams.

<!-- read more -->

## Initial Assessment
```
Hey, this bank forgot to do a pentest? Wanna... do an ethical?
```

The challenge description hinted towards this being a "pentest" challenge. Without any source, and very little to go on, I used the `big.txt` wordlist from [SecLists](https://github.com/danielmiessler/SecLists) combined with [ffuf](https://github.com/ffuf/ffuf) to enumerate content.

```

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://193.57.159.27:37407/FUZZ
 :: Wordlist         : FUZZ: big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 654
________________________________________________

apicache                [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 29ms]rors: 0 ::
api_test                [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 31ms]rors: 0 ::
api3                    [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 32ms]rors: 0 ::
api4                    [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 33ms]rors: 0 ::
api-doc                 [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 33ms]rors: 0 ::
apimage                 [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 33ms]rors: 0 ::
api2                    [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 35ms]rors: 0 ::
api                     [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 91ms]rors: 0 ::
apis                    [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 593ms]rs: 0 :::
favicon.ico             [Status: 200, Size: 3870, Words: 16, Lines: 13, Duration: 26ms]: 0 ::
images                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 30ms]ors: 0 ::
oauth                   [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 29ms]rrors: 0 ::
robots.txt              [Status: 200, Size: 67, Words: 3, Lines: 4, Duration: 28ms]rrors: 0 ::
static                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 44ms]rors: 0 ::
```
It seems that /api/ and /oauth/ endpoints exist. I further fuzzed these, which revealed some more interesting paths:

```
account                 [Status: 405, Size: 31, Words: 3, Lines: 1, Duration: 503ms]s: 0 :::
docs                    [Status: 200, Size: 939, Words: 150, Lines: 31, Duration: 308ms]0 ::
login                   [Status: 405, Size: 31, Words: 3, Lines: 1, Duration: 394ms]ors: 0 ::
ping                    [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 993ms]rs: 0 :::
status                  [Status: 200, Size: 66, Words: 1, Lines: 1, Duration: 700ms]rs: 0 :::
verify                  [Status: 405, Size: 31, Words: 3, Lines: 1, Duration: 312ms]rs: 0 :::
```

## Understanding The Problem
Reading the `/api/docs` endpoint revealed all the information we needed to interact with the API. `/api/verify` and `/api/account` endpoints appeared to exist behind authentication. POSTing to these endpoints with an access_token would return `{"logged_in": false}` which shows that we were not authenticated!

It's clear we will need to takeover a user's account. The login endpoint accepts an email and password combination. From reading the `/team` page, we can see a list of emails. It would make sense to use this information to takeover a specific user's account. Scrolling down, we can see "Reina Turner" listed as administrator. It seems likely that he is the intended target.

The team page pulls this information from the `main.js` file. Reading this source, we can see the object includes the user emails. We now have Reina's email address!

`{"first_name":"Reina","last_name":"Turner","emails":"Reina.Turner@fakebank.com","img":"person9","role":"Administrator"}`

## Exploiting Authentication
Reading further along the `main.js` file, we can see a number of functions which are designed to be used from the admin dashboard. I searched for the endpoints I knew about (`/oauth` and `/api`). 

This is where I found the following code:

```js
return e.next = 2, new Promise((function(e, t) {
	c().post("/api/account", {
		access_token: n
	}).then((function(t) {
		return e(t)
	}))
}));
```                                                                             

We can see that it's posting to the API endpoint with an access token, the value of which is a variable called `n`. Where does this come from?

```js
var n = localStorage.getItem("token");
```

Just a few lines above, we can see it is loaded from local storage. So, I figured if it's loading from localStorage using javascript, it'll have to save to localStorage using javascript somewhere else in the file. Searching for `localStorage.setItem` I found the following:

```js
r = p(t).then((function(e) {
	return e
})), localStorage.setItem("token", r), e.next = 9;
```

So it loads the value of p(t). What is `p()` and what is `t`?

```js
return e.next = 2, c().post("/oauth/login", {
	email: t,
	password: n
});
```

Just a few lines above that, we see `t` is being used as the value for the email address of a user.

```js
p = function(e) {
                    var t = new Date,
                        n = Math.floor(t.getTime() / 1e3),
                        r = e + Number.toString(n),
                        o = (new TextEncoder).encode(r);
                    return crypto.subtle.digest("SHA-256", o).then((function(e) {
                        return Array.from(new Uint8Array(e)).map((function(e) {
                            return e.toString(16).padStart(2, "0")
                        })).join("")
                    }))
                };
```

And then we see that the function `p()` is loading the timestamp of login, concatenating it onto the email (`e`) and then running it through the SHA-256 hashing algorithm (along with some padding and other stuff). This is great, but what time do we use for the timestamp?

Well, this is where reconnaissance comes in. Earlier I discovered the endpoint `/api/status` which conveniently stored the timestamp of the last admin login.

`{"last_build_time":1656930000,"last_admin_access_time":1656931175}`

Armed with this, I could add that value to the end of the email, and then run it through the SHA-256 method described in the above `p()` function.

## Final Notes
Credit to other Team Ireland Without RE members who helped out with this. You can find me on Twitter [@LooseSecurity](https://twitter.com/LooseSecurity).
