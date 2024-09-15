from django import template

register = template.Library()

@register.filter
def human_readable_size(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return value

    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024:
            return f"{value} {unit}"
        value //= 1024
    return f"{value} PB"