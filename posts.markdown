---
layout: default
title: Cillian.Tech
---

<div align="middle">
    <h1>Posts</h1>
    {% for post in site.posts %}
    <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
    <span class="post-date">{{ post.date | date: "%B %d, %Y" }}</span>
    {{ post.excerpt }}
    <hr>
    {% endfor %}
</div>