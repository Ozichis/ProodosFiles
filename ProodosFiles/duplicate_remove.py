def remove_duplicate(list):
    result = []
    for item in list:
        if item not in result:
            result.append(item)
    return result