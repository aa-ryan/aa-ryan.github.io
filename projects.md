---

layout: page
title: Others
permalink: /Projects/

---


## Interests

{% assign thumbnail="left" %}
{% for pic in page.images %}
{% if pic.path %}
{% include image.html url=pic.path caption="" width="150px" align=thumbnail %}
{% endif %}
{% endfor %}<br/>

## Extracurricular Activities

{% assign thumbnail="left" %}
{% for act in page.activities %}
{% if act.image %}
{% include image.html url=act.image caption="" width="250px" align=thumbnail %}
{% endif %}
**{{act.title}}** <br/>
*{{act.year}}* <br/>
{{ act.comment }}
{% endfor %}<br/>
