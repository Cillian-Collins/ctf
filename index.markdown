---
layout: default
title: Cillian.Tech
---
<div>
    <img align="left" src="assets/images/profile.gif">
    <div align="middle">
        <h1>Posts</h1>
        {% for post in site.posts limit:5 %}
            <article>
                <h4>
                <a href="{{ post.url }}">{{ post.title }}</a>
                <span>
                <time datetime="{{ post.date | date: "%Y-%m-%d" }}">({{ post.date | date_to_long_string }})</time>
                </span>
                </h4>
            </article>
        {% endfor %}
        <h4><a href="/posts">Read more...</a></h4>
    </div>
</div>
<div align="left">
<hr>
</div>