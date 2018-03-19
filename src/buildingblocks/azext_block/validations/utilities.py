def full_qual_name(fn):
    if not callable(fn):
        raise TypeError()
    return ".".join((fn.__module__, fn.__qualname__))

def unique(items, attribute_name=None):
    if items is None:
        return items
    if not isinstance(items, list):
        raise ValueError('items must be a list')
    extractor = (lambda x: getattr(x, attribute_name)) if attribute_name else (lambda x: x)
    unique_items = []
    for item in items:
        value = extractor(item)
        if not value in unique_items:
            unique_items.append(value)
    return unique_items

def duplicates(items, attribute_name=None):
    if items is None:
        return items
    if not isinstance(items, list):
        raise ValueError('items must be a list')
    extractor = (lambda x: getattr(x, attribute_name)) if attribute_name else (lambda x: x)
    seen_items = set()
    duplicate_items = set()
    seen_add = seen_items.add
    duplicates_add = duplicate_items.add
    for item in items:
        value = extractor(item)
        if value in seen_items:
            duplicates_add(value)
        else:
            seen_add(value)
    return list(duplicate_items)
