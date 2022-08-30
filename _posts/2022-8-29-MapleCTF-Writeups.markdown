
---
layout: post
title: CTFZone Writeups
author: Cillian
tags: [ctf, web, osint]
---
In this post I'll walk through the solutions for various challenges I solved at the MapleCTF 2022.

<!-- read more -->

## Pickle

This challenge presented us with a page, requesting a JSON object for code processing.
![We can send code for processing, and view the output](https://i.imgur.com/Zu8h3zD.png)

The code passed is then shown. If we pass a JSON object with some text containing a template such as `{{7*7}}` it will be rendered as `49`.

This is a Server-Side Template Injection challenge. The intended solution involved using SSTI to fetch the unpickle function and deserialize a payload. Fortunately, they only used a simple block list which was easily bypassed by a number of different payloads.

Their implementation of a block list, was to set the following values to ``None``: ``['self', 'config', 'request', 'session', 'g', 'app']``

This means we can't fetch any useful information from the above variables.

I decided to use the short lipsum payload. It's a really compact SSTI payload for python apps, and this evaded the block list.
```
{{lipsum.__globals__.os.popen('ls').read()}}
```

This shows us a directory listing. We now have code execution, so we can simply look around for the flag and cat it.

And we see it! A file named `flag.log`. Final payload:

```
{"test": "{{lipsum.__globals__.os.popen('cat flag.log').read()}}"}
```
