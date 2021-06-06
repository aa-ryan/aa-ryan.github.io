---

layout: page
title: Others
permalink: /Projects/

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
