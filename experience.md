---

layout: page
permalink: /experience/
title: Experiences


edus:
    - title:   "Dayananda Sagar Institutions"
      image: "/images/logo.png"
      comment: "-- Bachelor of Engineering, Computer Science and Technology<br/>"
	
---

## Education

{% assign thumbnail="left" %}
{% for edu in page.edus %}
{% if edu.image %}
{% include image.html url=edu.image caption="" height="100px" align=thumbnail %}
{% endif %}
**{{edu.title}}** <br/>
{{ edu.comment }}
{% endfor %}<br/>
