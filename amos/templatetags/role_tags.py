"""
amos/templatetags/role_tags.py

Custom template filter for checking role/group membership from templates.

Usage:
    {% load role_tags %}
    {% if user|has_role:"instructor" %}...{% endif %}

Docs: https://docs.djangoproject.com/en/5.2/howto/custom-template-tags/#writing-custom-template-filters
Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#groups
"""

from django import template

register = template.Library()


@register.filter(name="has_role")
def has_role(user, role_name):
    """Return True if *user* is a member of the named role group.

    Always returns False for anonymous (unauthenticated) users, so templates
    do not need a separate ``is_authenticated`` guard before calling this filter.
    """
    if not user.is_authenticated:
        return False
    return user.groups.filter(name=role_name).exists()
